# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  common_labels = {
    app         = "securevault"
    environment = var.environment
    managed_by  = "terraform"
  }
}

#-------------------------------------------------------------------------------
# VPC for private Cloud Function egress
#-------------------------------------------------------------------------------
resource "google_compute_network" "securevault" {
  name                    = "securevault-network"
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "deny_all_ingress" {
  name        = "securevault-deny-all-ingress"
  network     = google_compute_network.securevault.name
  direction   = "INGRESS"
  priority    = 1000
  description = "Default deny-all ingress for the SecureVault VPC"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_subnetwork" "securevault" {
  name                       = "securevault-subnet"
  ip_cidr_range              = "10.0.0.0/28"
  region                     = var.region
  network                    = google_compute_network.securevault.id
  private_ip_google_access   = true
  private_ipv6_google_access = "ENABLE_OUTBOUND_VM_ACCESS_TO_GOOGLE"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

#-------------------------------------------------------------------------------
# KMS key ring and CMEK key
#-------------------------------------------------------------------------------
resource "google_kms_key_ring" "securevault" {
  name     = "securevault-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "securevault" {
  name            = "securevault-key"
  key_ring        = google_kms_key_ring.securevault.id
  rotation_period = var.kms_key_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }

  labels = local.common_labels
}

# Grant BigQuery service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "bigquery_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:bq-${data.google_project.project.number}@bigquery-encryption.iam.gserviceaccount.com"
}

# Grant Cloud Storage service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "storage_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# Grant Pub/Sub service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "pubsub_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

#-------------------------------------------------------------------------------
# VPC connector for the Cloud Function
#-------------------------------------------------------------------------------
resource "google_vpc_access_connector" "securevault" {
  name          = "securevault-connector"
  region        = var.region
  network       = google_compute_network.securevault.id
  ip_cidr_range = "10.0.1.0/28"
  min_instances = 0
  max_instances = 2
}

#-------------------------------------------------------------------------------
# Cloud Router + NAT for controlled egress from the VPC connector subnet
#-------------------------------------------------------------------------------
resource "google_compute_router" "securevault" {
  name    = "securevault-router"
  region  = var.region
  network = google_compute_network.securevault.id
}

resource "google_compute_router_nat" "securevault" {
  name                               = "securevault-nat"
  router                             = google_compute_router.securevault.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }

  depends_on = [google_compute_router.securevault]
}

#-------------------------------------------------------------------------------
# Service account for the Cloud Function
# Least-privilege: no project editor/owner, only required roles.
#-------------------------------------------------------------------------------
resource "google_service_account" "scc_processor" {
  # Cost: free
  account_id   = "scc-processor"
  display_name = "SecureVault SCC Processor Function"
  description  = "Dedicated runtime identity for the scc-processor Cloud Function"
}

#-------------------------------------------------------------------------------
# Pub/Sub topic for SCC findings
# Cost: first 10 GiB/month free, then ~$40/TiB; 1-day retention keeps cost low.
#-------------------------------------------------------------------------------
resource "google_pubsub_topic" "scc_findings" {
  name = "scc-findings"

  message_retention_duration = "86400s" # 1 day (default is 7 days; short retention reduces cost)

  kms_key_name = google_kms_crypto_key.securevault.id

  labels = local.common_labels
}

# Restrict publishers to SCC notification service account only.
# The SCC notification service account is a Google-managed identity of the form
# service-{PROJECT_NUMBER}@gcp-sa-scc-notification.iam.gserviceaccount.com.
resource "google_pubsub_topic_iam_member" "scc_publisher" {
  topic  = google_pubsub_topic.scc_findings.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-scc-notification.iam.gserviceaccount.com"
}

#-------------------------------------------------------------------------------
# Secret Manager: Brevo API key
# The secret container is created here; the version must be added manually after
# terraform apply so the key value never enters Terraform state.
# Cost: ~$0.06 per active version per month if populated; free tier 6 active versions.
#-------------------------------------------------------------------------------
resource "google_secret_manager_secret" "brevo_api_key" {
  secret_id = "brevo-api-key"

  replication {
    auto {}
  }

  labels = local.common_labels
}

# Allow the function runtime to mount the secret via secret_environment_variables.
resource "google_secret_manager_secret_iam_member" "function_brevo_accessor" {
  secret_id = google_secret_manager_secret.brevo_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scc_processor.email}"
}

#-------------------------------------------------------------------------------
# Cloud Storage bucket for Cloud Function source code
# Cost: ~$0.020/GB/month; source zip is <1 MB.
#-------------------------------------------------------------------------------
resource "google_storage_bucket" "source_logs" {
  #checkov:skip=CKV_GCP_62:This bucket is the access-log destination; requiring it to log itself would create an infinite loop.
  name          = "${var.project_id}-securevault-source-logs"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.securevault.id
  }

  labels = local.common_labels

  depends_on = [
    google_kms_crypto_key_iam_member.storage_encrypt_decrypt,
  ]
}

# Cloud Storage access logs are written by Google's analytics service account.
resource "google_storage_bucket_iam_member" "source_logs_analytics_writer" {
  bucket = google_storage_bucket.source_logs.name
  role   = "roles/storage.legacyBucketWriter"
  member = "serviceAccount:cloud-storage-analytics@google.com"
}

resource "google_storage_bucket" "source" {
  name          = "${var.project_id}-securevault-source"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.securevault.id
  }

  logging {
    log_bucket        = google_storage_bucket.source_logs.name
    log_object_prefix = "access-logs/"
  }

  labels = local.common_labels

  depends_on = [
    google_kms_crypto_key_iam_member.storage_encrypt_decrypt,
    google_storage_bucket_iam_member.source_logs_analytics_writer,
  ]
}

#-------------------------------------------------------------------------------
# Cloud Function Gen 2
# Cost: free tier 2M invocations/month; 256 MB keeps memory charge low.
#-------------------------------------------------------------------------------
data "archive_file" "function_source" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/../src.zip"
}

resource "google_storage_bucket_object" "function_source" {
  name   = "scc-processor-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.source.name
  source = data.archive_file.function_source.output_path
}

resource "google_cloudfunctions2_function" "scc_processor" {
  name        = "scc-processor"
  location    = var.region
  description = "SecureVault SCC finding processor"

  build_config {
    runtime     = "python311"
    entry_point = "scc_processor.main.process_scc_finding"
    source {
      storage_source {
        bucket = google_storage_bucket.source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    available_memory              = "256M"
    timeout_seconds               = 60
    max_instance_count            = 10
    min_instance_count            = 0
    ingress_settings              = "ALLOW_INTERNAL_ONLY"
    vpc_connector_egress_settings = "ALL_TRAFFIC"
    service_account_email         = google_service_account.scc_processor.email
    vpc_connector                 = google_vpc_access_connector.securevault.id

    environment_variables = {
      PROJECT_ID       = var.project_id
      REGION           = var.region
      ALERT_EMAIL      = var.alert_email
      BIGQUERY_DATASET = google_bigquery_dataset.analytics.dataset_id
      BIGQUERY_TABLE   = google_bigquery_table.findings_history.table_id
      LOG_LEVEL        = "INFO"
    }

    secret_environment_variables {
      key        = "BREVO_API_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.brevo_api_key.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.scc_findings.id
    retry_policy   = "RETRY_POLICY_RETRY"
    # service_account_email intentionally omitted; Eventarc uses its own managed identity.
  }

  labels = local.common_labels

  depends_on = [
    google_secret_manager_secret_iam_member.function_brevo_accessor,
    google_project_service.services,
  ]
}

#-------------------------------------------------------------------------------
# Firestore (Native mode)
# Cost: first ~600k writes/month (20k/day), 1 GiB storage free.
#-------------------------------------------------------------------------------
resource "google_firestore_database" "default" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.firestore_location
  type        = "FIRESTORE_NATIVE"

  app_engine_integration_mode = "DISABLED"

  depends_on = [google_project_service.services]
}

#-------------------------------------------------------------------------------
# BigQuery dataset and findings_history table
# Cost: first 10 GiB storage and 1 TiB query free per month.
#-------------------------------------------------------------------------------
resource "google_bigquery_dataset" "analytics" {
  dataset_id  = "securevault_analytics"
  description = "SecureVault findings and remediation analytics"
  location    = var.bigquery_location

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.securevault.id
  }

  labels = local.common_labels

  depends_on = [
    google_kms_crypto_key_iam_member.bigquery_encrypt_decrypt,
  ]
}

resource "google_bigquery_table" "findings_history" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "findings_history"
  deletion_protection = true

  schema = file("${path.module}/bigquery_schema.json")

  time_partitioning {
    type          = "DAY"
    field         = "timestamp"
    expiration_ms = null
  }

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.securevault.id
  }

  labels = local.common_labels

  depends_on = [
    google_kms_crypto_key_iam_member.bigquery_encrypt_decrypt,
  ]
}

# Allow the function to stream rows into BigQuery.
resource "google_bigquery_dataset_iam_member" "function_bigquery_data_editor" {
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.scc_processor.email}"
}

# Allow the function to run BigQuery jobs (required for streaming inserts).
resource "google_project_iam_member" "function_bigquery_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.scc_processor.email}"
}

# Allow Firestore writes.
resource "google_project_iam_member" "function_firestore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.scc_processor.email}"
}

# Allow Cloud Logging.
resource "google_project_iam_member" "function_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.scc_processor.email}"
}

# Allow the function to update SCC finding state (e.g., mute after remediation).
resource "google_project_iam_member" "function_scc_findings_editor" {
  project = var.project_id
  role    = "roles/securitycenter.findingsEditor"
  member  = "serviceAccount:${google_service_account.scc_processor.email}"
}

# Allow Cloud Monitoring metric writing.
resource "google_project_iam_member" "function_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.scc_processor.email}"
}

#-------------------------------------------------------------------------------
# Custom least-privilege role for auto-remediation actions
#-------------------------------------------------------------------------------
resource "google_project_iam_custom_role" "remediation" {
  role_id     = "securevault.remediator"
  title       = "SecureVault Auto-Remediator"
  description = "Minimal permissions for SecureVault critical-finding auto-remediation"

  permissions = [
    # Storage: remove allUsers/allAuthenticatedUsers from bucket IAM
    "storage.buckets.get",
    "storage.buckets.setIamPolicy",
    # Compute: disable open firewall rules
    "compute.firewalls.get",
    "compute.firewalls.update",
    # IAM: remove excess roles from service accounts
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.setIamPolicy",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",
  ]
}

resource "google_project_iam_member" "function_remediator" {
  project = var.project_id
  role    = google_project_iam_custom_role.remediation.id
  member  = "serviceAccount:${google_service_account.scc_processor.email}"
}

#-------------------------------------------------------------------------------
# Log-based metric and alert for critical findings
#-------------------------------------------------------------------------------
resource "google_logging_metric" "securevault_finding" {
  name        = "securevault_finding"
  description = "SecureVault processed findings by severity and class"
  filter      = "resource.type=\"cloud_function\" labels.function_name=\"scc-processor\" jsonPayload.message=\"Finding processing complete\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "severity"
      value_type  = "STRING"
      description = "Finding severity"
    }
    labels {
      key         = "finding_class"
      value_type  = "STRING"
      description = "Finding class"
    }
  }

  label_extractors = {
    "severity"      = "EXTRACT(jsonPayload.finding_severity)"
    "finding_class" = "EXTRACT(jsonPayload.finding_class)"
  }
}

resource "google_monitoring_alert_policy" "critical_finding" {
  display_name = "SecureVault Critical Finding Detected"
  combiner     = "OR"

  conditions {
    display_name = "Critical finding processed"
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND metric.type=\"logging.googleapis.com/user/securevault_finding\" AND metric.labels.severity=\"CRITICAL\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  user_labels = local.common_labels
}

#-------------------------------------------------------------------------------
# Cloud Monitoring dashboard
# Cost: dashboard creation free; metric reads within free tier.
#-------------------------------------------------------------------------------
resource "google_monitoring_dashboard" "securevault" {
  dashboard_json = jsonencode({
    displayName = "SecureVault Dashboard"
    gridLayout = {
      columns = "2"
      widgets = [
        {
          title = "Findings by Severity (24h)"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"cloud_function\" metric.type=\"logging.googleapis.com/user/securevault_finding\" metric.labels.severity!=\"\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_RATE"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.severity"]
                  }
                }
              }
            }]
          }
        },
        {
          title = "Auto-remediation Success/Failure Rate"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"cloud_function\" metric.type=\"logging.googleapis.com/user/securevault_remediation\" metric.labels.status!=\"\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_RATE"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.status"]
                  }
                }
              }
            }]
          }
        },
        {
          title = "Top Finding Classes"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"cloud_function\" metric.type=\"logging.googleapis.com/user/securevault_finding\" metric.labels.finding_class!=\"\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_RATE"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.finding_class"]
                  }
                }
              }
            }]
          }
        },
        {
          title = "Brevo Alert Delivery Status"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"cloud_function\" metric.type=\"logging.googleapis.com/user/securevault_alert\" metric.labels.status!=\"\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_RATE"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.status"]
                  }
                }
              }
            }]
          }
        }
      ]
    }
  })
}

#-------------------------------------------------------------------------------
# Alert policy: Cloud Function error rate > 5% over 5 minutes
# Cost: free alert policies; notification channels may cost if non-email.
#-------------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "function_error_rate" {
  display_name = "SecureVault Function Error Rate > 5%"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Function error ratio exceeds 5%"
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" AND metric.labels.status!=\"ok\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.05
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_FRACTION_TRUE"
      }
      denominator_filter = "resource.type=\"cloud_function\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_count\""
      denominator_aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  user_labels = local.common_labels
}

resource "google_monitoring_notification_channel" "email" {
  # Cost: email notifications from Cloud Monitoring are free.
  display_name = "SecureVault Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

#-------------------------------------------------------------------------------
# Project-level APIs
#-------------------------------------------------------------------------------
resource "google_project_service" "services" {
  for_each = toset([
    "securitycenter.googleapis.com",
    "pubsub.googleapis.com",
    "cloudfunctions.googleapis.com",
    "secretmanager.googleapis.com",
    "firestore.googleapis.com",
    "bigquery.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com",
    "cloudasset.googleapis.com",
    "iam.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "vpcaccess.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

#-------------------------------------------------------------------------------
# Data sources
#-------------------------------------------------------------------------------
data "google_project" "project" {
  project_id = var.project_id
}
