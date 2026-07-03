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
  # checkov:skip=CKV_GCP_83: Risk accepted. CMEK for this topic would require a Cloud KMS key ring/key (~$1/key/month + operations) and key-management overhead that exceeds the $5/month hobby-project target. The topic contains only transient SCC notification messages, uses IAM-restricted publishing (SCC notification SA only), and no sensitive payload data is stored long-term. See context/THREAT_MODEL.md (poisoned-finding scenario) and adr/ADR-007-threat-model-and-trust-boundaries.md.
  # Cost: ~$0 for low-volume SCC notifications under free tier.
  name = "scc-findings"

  message_retention_duration = "86400s" # 1 day (default is 7 days; short retention reduces cost)

  labels = {
    app     = "securevault"
    purpose = "scc-notifications"
  }
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
# The secret itself is created here; the version must be added manually after
# terraform apply so the key value never enters Terraform state.
# Cost: ~$0.06 per secret version per month if populated; free tier 6 active versions.
#-------------------------------------------------------------------------------
resource "google_secret_manager_secret" "brevo_api_key" {
  # Cost: ~$0.06/month per active version after free tier.
  secret_id = "brevo-api-key"

  replication {
    auto {}
  }

  labels = {
    app = "securevault"
  }
}

# Allow the function service account to access the secret.
resource "google_secret_manager_secret_iam_member" "function_brevo_accessor" {
  secret_id = google_secret_manager_secret.brevo_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scc_processor.email}"
}

#-------------------------------------------------------------------------------
# Cloud Storage bucket for Cloud Function source code
# Cost: ~$0.020/GB/month; source zip is <1 MB.
#-------------------------------------------------------------------------------
resource "google_storage_bucket" "source" {
  # checkov:skip=CKV_GCP_62: Risk accepted. Access logging is disabled because this bucket stores only ephemeral Cloud Function source zip artifacts, not sensitive data. Uniform bucket-level access and public-access prevention are enforced, and the bucket is not exposed to external principals. Enabling access logging would require an additional log bucket and add near-zero-but-non-zero cost; the security value is low for this non-sensitive data. See context/THREAT_MODEL.md and adr/ADR-007-threat-model-and-trust-boundaries.md.
  # checkov:skip=CKV_GCP_78: Risk accepted. Versioning is disabled because source zips are rebuild artifacts. Old versions provide no security value for this non-sensitive bucket, and enabling versioning would increase storage cost for no operational benefit. See context/THREAT_MODEL.md and adr/ADR-007-threat-model-and-trust-boundaries.md.
  # Cost: ~$0.02/GB/month; source zip < 1 MB.
  name          = "${var.project_id}-securevault-source"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  public_access_prevention = "enforced"

  labels = {
    app = "securevault"
  }
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
  # Cost: free tier 2M requests/month; 256 MiB memory tier.
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
    available_memory      = "256M"
    timeout_seconds       = 60
    max_instance_count    = 10
    min_instance_count    = 0
    ingress_settings      = "ALLOW_INTERNAL_ONLY"
    service_account_email = google_service_account.scc_processor.email
    environment_variables = {
      PROJECT_ID       = var.project_id
      REGION           = var.region
      ALERT_EMAIL      = var.alert_email
      BREVO_SECRET_ID  = google_secret_manager_secret.brevo_api_key.secret_id
      BIGQUERY_DATASET = google_bigquery_dataset.analytics.dataset_id
      BIGQUERY_TABLE   = google_bigquery_table.findings_history.table_id
      LOG_LEVEL        = "INFO"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.scc_findings.id
    retry_policy   = "RETRY_POLICY_RETRY"
    # Note: service_account_email is intentionally omitted here. For a Pub/Sub
    # trigger the Eventarc control plane uses its own managed service account to
    # invoke the function; setting the function runtime SA in this block is
    # incorrect and causes trigger creation failures.
  }

  labels = {
    app = "securevault"
  }

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
  # Cost: free tier generous for low-volume audit logs.
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
  # checkov:skip=CKV_GCP_81: Risk accepted. Default GCP-managed encryption (Google-managed encryption key) satisfies analytics needs for this low-sensitivity finding data. Configuring CMEK would require a Cloud KMS key ring/key, key-management overhead, and additional cost that is not justified under the $5/month hobby-project target. See context/THREAT_MODEL.md and adr/ADR-007-threat-model-and-trust-boundaries.md.
  # Cost: free storage under 10 GiB; partitioned table minimizes scanned bytes.
  dataset_id  = "securevault_analytics"
  description = "SecureVault findings and remediation analytics"
  location    = var.bigquery_location

  labels = {
    app = "securevault"
  }
}

resource "google_bigquery_table" "findings_history" {
  # checkov:skip=CKV_GCP_80: Risk accepted. Default GCP-managed encryption is sufficient for findings analytics. CMEK is not justified under the $5/month target and would introduce key-management overhead. See context/THREAT_MODEL.md and adr/ADR-007-threat-model-and-trust-boundaries.md.
  # checkov:skip=CKV_GCP_121: Risk accepted. Deletion protection is disabled to allow cost-controlled cleanup of the analytics table. The same data is replicated to Firestore (operational state) and captured in Cloud Audit Logs, so accidental deletion does not destroy the only copy of audit evidence. See context/THREAT_MODEL.md and adr/ADR-007-threat-model-and-trust-boundaries.md.
  # Cost: date partitioning reduces query cost significantly.
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  table_id   = "findings_history"

  schema = file("${path.module}/bigquery_schema.json")

  time_partitioning {
    type          = "DAY"
    field         = "timestamp"
    expiration_ms = null
  }

  labels = {
    app = "securevault"
  }
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

# Allow reading its own secrets.
resource "google_project_iam_member" "function_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
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
# Cloud Monitoring dashboard
# Cost: dashboard creation free; metric reads within free tier.
#-------------------------------------------------------------------------------
resource "google_monitoring_dashboard" "securevault" {
  # Cost: free.
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
  # Cost: free.
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

  user_labels = {
    app = "securevault"
  }
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
