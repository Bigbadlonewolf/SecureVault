# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

variable "project_id" {
  description = "GCP project ID where SecureVault is deployed"
  type        = string
}

variable "region" {
  description = "Primary GCP region for compute resources"
  type        = string
  default     = "us-central1"
}

variable "firestore_location" {
  description = "Firestore database location (must be region or multi-region value)"
  type        = string
  default     = "nam5"
}

variable "bigquery_location" {
  description = "BigQuery dataset location"
  type        = string
  default     = "US"
}

variable "alert_email" {
  description = "Email address to receive Brevo and Cloud Monitoring alerts"
  type        = string
}

