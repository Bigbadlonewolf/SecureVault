# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "pubsub_topic" {
  description = "Pub/Sub topic receiving SCC findings"
  value       = google_pubsub_topic.scc_findings.name
}

output "cloud_function_name" {
  description = "Name of the deployed Cloud Function"
  value       = google_cloudfunctions2_function.scc_processor.name
}

output "service_account_email" {
  description = "Email of the dedicated Cloud Function service account"
  value       = google_service_account.scc_processor.email
}

output "bigquery_dataset" {
  description = "BigQuery dataset for analytics"
  value       = google_bigquery_dataset.analytics.dataset_id
}

output "bigquery_table" {
  description = "BigQuery findings history table"
  value       = google_bigquery_table.findings_history.table_id
}

output "monitoring_dashboard" {
  description = "SecureVault monitoring dashboard"
  value       = google_monitoring_dashboard.securevault.id
}

output "remediation_custom_role" {
  description = "Custom IAM role used for auto-remediation actions"
  value       = google_project_iam_custom_role.remediation.id
}
