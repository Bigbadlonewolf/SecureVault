terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.7"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "securitycenter.googleapis.com",
    "pubsub.googleapis.com",
    "cloudfunctions.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudbuild.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_findings" {
  name = "scc-findings-topic"
  depends_on = [google_project_service.apis["pubsub.googleapis.com"]]
}

# Service account for Cloud Function
resource "google_service_account" "function_sa" {
  account_id   = "securevault-function"
  display_name = "SecureVault Cloud Function"
  description  = "Service account for SecureVault security findings handler"
}

# Grant function SA permission to read Pub/Sub messages
resource "google_project_iam_member" "function_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

# Grant function SA permission to read SCC findings
resource "google_project_iam_member" "function_scc_viewer" {
  project = var.project_id
  role    = "roles/securitycenter.findingsViewer"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

# Secret Manager for SendGrid API key
resource "google_secret_manager_secret" "sendgrid_key" {
  secret_id = "securevault-sendgrid-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "sendgrid_key" {
  secret      = google_secret_manager_secret.sendgrid_key.id
  secret_data = var.sendgrid_api_key
}

# Grant function SA access to the secret
resource "google_secret_manager_secret_iam_member" "function_secret_access" {
  secret_id = google_secret_manager_secret.sendgrid_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.function_sa.email}"
}

# GCS bucket for function source code
resource "google_storage_bucket" "source" {
  name          = "${var.project_id}-securevault-source"
  location      = var.region
  force_destroy = true
  uniform_bucket_level_access = true
}

# Package source code
data "archive_file" "source" {
  type        = "zip"
  source_dir  = "${path.module}/../"
  output_path = "${path.module}/../function-source.zip"
  excludes    = [
    "terraform/**",
    "tests/**",
    ".github/**",
    "docs/**",
    "function-source.zip",
    ".git/**",
    ".gitignore",
    "README.md",
  ]
}

# Upload source code
resource "google_storage_bucket_object" "source" {
  name   = "function-source-${data.archive_file.source.output_md5}.zip"
  bucket = google_storage_bucket.source.name
  source = data.archive_file.source.output_path
}

# Cloud Function v2
resource "google_cloudfunctions2_function" "scc_handler" {
  name     = "securevault-scc-handler"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "scc_alert_handler"
    source {
      storage_source {
        bucket = google_storage_bucket.source.name
        object = google_storage_bucket_object.source.name
      }
    }
  }

  service_config {
    available_memory       = "256M"
    timeout_seconds        = 60
    max_instance_count     = 10
    service_account_email  = google_service_account.function_sa.email
    environment_variables = {
      ALERT_EMAIL      = var.alert_email
      ALERT_FROM_EMAIL = var.alert_from_email
    }
    secret_environment_variables {
      key        = "SENDGRID_API_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.sendgrid_key.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.scc_findings.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.function_sa.email
  }

  depends_on = [google_project_service.apis["cloudfunctions.googleapis.com"]]
}

# Log sink: SCC findings → Pub/Sub
resource "google_logging_project_sink" "scc_to_pubsub" {
  name        = "securevault-scc-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.scc_findings.id}"
  filter      = <<EOT
protoPayload.serviceName="securitycenter.googleapis.com"
protoPayload.methodName="google.cloud.securitycenter.v1.SecurityCenter.CreateFinding"
EOT
  unique_writer_identity = true
}

# Grant log sink writer permission to publish to Pub/Sub
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.scc_findings.id
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.scc_to_pubsub.writer_identity
}
