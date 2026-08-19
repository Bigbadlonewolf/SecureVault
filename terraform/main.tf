# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    # google-beta exists solely for google_project_service_identity, which is
    # beta-only in provider 5.x. See the service-agent block below for why the
    # CMEK grants cannot be written without it.
    google-beta = {
      source  = "hashicorp/google-beta"
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

provider "google-beta" {
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
# No VPC. Cloud Function egress goes over Google-managed networking.
#
# ADR-009 removed google_compute_network, google_compute_subnetwork,
# google_compute_firewall.deny_all_ingress, google_vpc_access_connector,
# google_compute_router, and google_compute_router_nat from this file.
#
# The VPC held no resources — no Cloud SQL, no Memorystore, no VMs — so the
# connector existed to reach private resources that did not exist. The only
# external egress target in the codebase is https://api.brevo.com; everything
# else is Google APIs, reachable without VPC egress. The connector and NAT were
# load-bearing for each other, not for the workload.
#
# ingress_settings = "ALLOW_INTERNAL_ONLY" is retained on the function and is
# independent of the connector. compute.googleapis.com stays enabled — the
# OPEN_FIREWALL remediation action needs it.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# KMS key ring and CMEK key
#-------------------------------------------------------------------------------
resource "google_kms_key_ring" "securevault" {
  name     = "securevault-keyring"
  location = var.region

  # cloudkms.googleapis.com is not enabled on a fresh project, and Terraform would
  # otherwise create this in parallel with enabling it. Every resource below that
  # touches a non-default API carries the same guard.
  depends_on = [google_project_service.services]
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

#-------------------------------------------------------------------------------
# Service agents (P4SAs) for the four services that encrypt with the CMEK key.
#
# These four blocks exist because a per-service agent is NOT guaranteed to exist
# just because its API is enabled. Constructing the address by string
# interpolation from the project number — which this file used to do — produces a
# well-formed principal that may name no account, and an IAM binding to a
# non-existent principal fails at apply. terraform validate cannot see this,
# because the string is syntactically perfect.
#
# Secret Manager is the hard case: its agent is never created implicitly at all.
# Google documents `gcloud beta services identity create --service=
# secretmanager.googleapis.com` as a required step before granting CMEK access
# (cloud.google.com/secret-manager/docs/cmek). google_project_service_identity is
# the Terraform equivalent, and is beta-only in provider 5.x — the sole reason
# google-beta is declared above.
#
# Storage and BigQuery have GA data sources that both look up and trigger
# creation of their agents, so they need no beta provider.
#-------------------------------------------------------------------------------
resource "google_project_service_identity" "secretmanager" {
  provider = google-beta
  service  = "secretmanager.googleapis.com"

  depends_on = [google_project_service.services]
}

resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  service  = "pubsub.googleapis.com"

  depends_on = [google_project_service.services]
}

data "google_storage_project_service_account" "gcs" {
  depends_on = [google_project_service.services]
}

data "google_bigquery_default_service_account" "bq" {
  depends_on = [google_project_service.services]
}

# Grant BigQuery service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "bigquery_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_bigquery_default_service_account.bq.email}"
}

# Grant Cloud Storage service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "storage_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

# Grant Pub/Sub service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "pubsub_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

# Grant Secret Manager service account access to the CMEK key.
resource "google_kms_crypto_key_iam_member" "secretmanager_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.securevault.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.secretmanager.email}"
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

  depends_on = [google_project_service.services]
}

#-------------------------------------------------------------------------------
# Service account for the Cloud Function build (Gen 2 / Cloud Build)
# Gen 2 defaults the build identity to the project's default *compute* SA. Under
# constraints/iam.automaticIamGrantsForDefaultServiceAccounts that account has no
# roles, so the build fails with a permissions error. A dedicated identity avoids
# re-privileging the shared default compute SA to fix it.
#-------------------------------------------------------------------------------
resource "google_service_account" "cloud_build" {
  # Cost: free
  account_id   = "securevault-build"
  display_name = "SecureVault Cloud Function build identity"
  description  = "Build-time identity for the scc-processor Cloud Function; no runtime access"

  depends_on = [google_project_service.services]
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

  depends_on = [
    google_kms_crypto_key_iam_member.pubsub_encrypt_decrypt,
    google_project_service.services,
  ]
}

# Deliberate absence: no publisher IAM binding for SCC, and no
# google_scc_notification_config anywhere in this repo.
#
# SCC continuous export to Pub/Sub requires Security Command Center Premium and
# org-level configuration. The service agent that would publish here,
# service-{PROJECT_NUMBER}@gcp-sa-scc-notification.iam.gserviceaccount.com, is
# only minted when a notification config is created. Binding it on a
# Standard-tier project fails at apply with "Service account ... does not
# exist" — the address interpolates cleanly from the project number and names
# nothing, which terraform validate cannot detect.
#
# The topic therefore has no explicit publisher grant. Publishing is limited to
# principals holding pubsub.publisher at the project level. If Premium is ever
# enabled, add the notification config and this binding together.

#-------------------------------------------------------------------------------
# Secret Manager: Brevo API key
# The secret container is created here; the version must be added manually after
# terraform apply so the key value never enters Terraform state.
# Cost: ~$0.06 per active version per month if populated; free tier 6 active versions.
#-------------------------------------------------------------------------------
resource "google_secret_manager_secret" "brevo_api_key" {
  secret_id = "brevo-api-key"

  # User-managed replication, not auto. CMEK under an automatic replication policy
  # requires a KMS key in the `global` location, and securevault-keyring is regional
  # (var.region). Pinning one replica to var.region lets this secret use the same
  # securevault-key as every other data store instead of forcing a second key ring —
  # and key rings can never be deleted, so declining to create one is the point.
  # The function runs in var.region, so a co-located single replica is also the
  # correct residency answer, not a compromise.
  replication {
    user_managed {
      replicas {
        location = var.region

        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.securevault.id
        }
      }
    }
  }

  labels = local.common_labels

  depends_on = [
    google_kms_crypto_key_iam_member.secretmanager_encrypt_decrypt,
    google_project_service.services,
  ]
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
  # Retained but no longer written to. It was the destination for legacy GCS
  # access logs; that mechanism was dropped because Domain Restricted Sharing
  # blocks the required cloud-storage-analytics grant (see below). Kept rather
  # than destroyed so the change is non-destructive; remove it deliberately if
  # the empty bucket is not wanted.
  #checkov:skip=CKV_GCP_62:Empty retained bucket with no writers; self-logging would serve no purpose.
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
    google_project_service.services,
  ]
}

# Deliberate absence: no legacy GCS access logging, and no
# cloud-storage-analytics@google.com grant.
#
# GCS access-log delivery requires granting roles/storage.legacyBucketWriter to
# the Google-owned group cloud-storage-analytics@google.com on the destination
# bucket. That principal is outside this Cloud Identity customer, so the
# organization's Domain Restricted Sharing constraint
# (constraints/iam.allowedPolicyMemberDomains) refuses the binding at apply with
# "One or more users named in the policy do not belong to a permitted customer".
# Granting an org-wide DRS exception for one legacy log mechanism is a worse
# trade than dropping the mechanism.
#
# Cloud Audit Logs data-access logging replaces it — see
# google_project_iam_audit_config below. That is the current mechanism, needs no
# cross-customer grant, and covers Secret Manager and KMS as well as Storage,
# which legacy bucket logs never did.

resource "google_storage_bucket" "source" {
  #checkov:skip=CKV_GCP_62:Legacy bucket-log delivery is unreachable here — it needs a roles/storage.legacyBucketWriter grant to cloud-storage-analytics@google.com, which Domain Restricted Sharing refuses at apply. Compensating control is the DATA_READ/DATA_WRITE audit config on storage.googleapis.com in this same file, which covers this bucket and is not skippable by an attacker who can edit bucket metadata.
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

  # No logging{} block. Access-log delivery to source_logs would require the
  # cloud-storage-analytics grant that Domain Restricted Sharing forbids (see
  # above). Configuring logging{} without that grant produces a bucket that
  # claims to ship access logs and silently never does, which is worse than not
  # configuring it. Read access to this bucket is captured by the DATA_READ
  # audit config on storage.googleapis.com instead.

  labels = local.common_labels

  depends_on = [
    google_kms_crypto_key_iam_member.storage_encrypt_decrypt,
    google_project_service.services,
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
    entry_point = "process_scc_finding"
    # Build identity. Without this the build runs as the default compute SA,
    # which holds no roles in this project and fails.
    service_account = google_service_account.cloud_build.id
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
    # The build SA's grants have no reference edge to this resource; without
    # these the build can start before the roles land and fail.
    google_project_iam_member.build_log_writer,
    google_project_iam_member.build_artifact_writer,
    google_project_iam_member.build_source_reader,
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
    google_project_service.services,
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
# Build service account roles
# The three roles Google documents as the minimum for a user-managed Gen 2 build
# identity. Build-time only: this SA never runs the function.
#-------------------------------------------------------------------------------
resource "google_project_iam_member" "build_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

# Push the built container image to the gcf-artifacts repository.
resource "google_project_iam_member" "build_artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
}

# Read the function source zip from the staging bucket.
resource "google_project_iam_member" "build_source_reader" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.cloud_build.email}"
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
    # IAM: read-only. The two setIamPolicy permissions that used to sit here were
    # provisioned for remove_excess_service_account_roles, the OVER_PRIVILEGED_SA
    # handler that ADR-004 excluded and v0.1.4 deleted (EVOLUTION.md). THREAT_MODEL.md
    # tracked them as debt "to revoke from the Terraform role once the handler is
    # either scoped safely or deleted" — the handler is gone, so they are revoked.
    # Granting a Cloud Function service account project-wide setIamPolicy for a code
    # path that no longer exists is standing privilege with nothing behind it.
    # The two reads below are equally orphaned but grant no write capability.
    "iam.serviceAccounts.get",
    "resourcemanager.projects.getIamPolicy",
  ]

  depends_on = [google_project_service.services]
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

  depends_on = [google_project_service.services]
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
      # ALIGN_FRACTION_TRUE only applies to BOOL metrics. execution_count is
      # DELTA/INT64, so the numerator must use the same aligner as the
      # denominator below; the ratio of the two rates is the error fraction.
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
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

  depends_on = [google_project_service.services]
}

#-------------------------------------------------------------------------------
# Cloud Audit Logs: data-access logging
#
# Admin Activity logs are always on and free. Data-access logs (DATA_READ /
# DATA_WRITE) are off by default on every GCP project, and this project's
# auditConfigs was empty before these blocks existed. THREAT_MODEL.md and
# ADR-007 both asserted that Secret Manager access and API calls were covered by
# Cloud Audit Logs; without these, that was false.
#
# Scoped to three services rather than allServices on purpose: data-access logs
# bill by volume, and these are the three that hold or gate the sensitive
# material. Storage covers the source bucket, replacing the legacy access logs
# that Domain Restricted Sharing blocked. Secret Manager covers reads of the
# Brevo API key. KMS covers every encrypt/decrypt against the CMEK, which is what
# makes the "revoke the key grant as a kill switch" claim auditable.
#
# google_project_iam_audit_config is authoritative per service: it replaces the
# audit config for the named service rather than merging into it.
#-------------------------------------------------------------------------------
resource "google_project_iam_audit_config" "storage" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [google_project_service.services]
}

resource "google_project_iam_audit_config" "secretmanager" {
  project = var.project_id
  service = "secretmanager.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [google_project_service.services]
}

resource "google_project_iam_audit_config" "cloudkms" {
  project = var.project_id
  service = "cloudkms.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [google_project_service.services]
}

#-------------------------------------------------------------------------------
# Project-level APIs
#-------------------------------------------------------------------------------
resource "google_project_service" "services" {
  for_each = toset([
    "securitycenter.googleapis.com",
    "pubsub.googleapis.com",
    "cloudfunctions.googleapis.com",
    # Cloud Functions Gen 2 is Cloud Run underneath: the build goes through Cloud
    # Build into Artifact Registry, the function runs as a Cloud Run service, and
    # the Pub/Sub trigger is an Eventarc trigger. Enabling cloudfunctions alone
    # leaves all four off on a fresh project. GCP sometimes pulls them in as
    # dependencies; that is not a contract, so they are declared.
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "eventarc.googleapis.com",
    "secretmanager.googleapis.com",
    "firestore.googleapis.com",
    "bigquery.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com",
    "cloudasset.googleapis.com",
    "iam.googleapis.com",
    "cloudkms.googleapis.com",
    # Retained after ADR-009: the OPEN_FIREWALL remediation action needs it.
    "compute.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

#-------------------------------------------------------------------------------
# Data sources
#
# google_project was removed with the SCC publisher binding above: the project
# number was used only to interpolate that service agent address, and an
# interpolated principal cannot be validated before apply. Service agents that
# are genuinely needed are declared as google_project_service_identity or read
# through a typed data source instead.
#-------------------------------------------------------------------------------
