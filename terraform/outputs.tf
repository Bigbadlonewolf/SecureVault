output "pubsub_topic" {
  description = "Pub/Sub topic for SCC findings"
  value       = google_pubsub_topic.scc_findings.id
}

output "cloud_function" {
  description = "Cloud Function URI"
  value       = google_cloudfunctions2_function.scc_handler.service_config[0].uri
}

output "service_account" {
  description = "Service account email used by the Cloud Function"
  value       = google_service_account.function_sa.email
}
