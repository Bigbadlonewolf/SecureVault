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
  # Must match the location of the CMEK key in google_kms_crypto_key.securevault,
  # which lives in var.region. A multi-region value such as "US" is rejected at
  # apply against a regional key: "The location for the specified Cloud KMS key
  # is us-central1. This location is not supported for the BigQuery dataset
  # location US." Changing this to a multi-region requires a second key ring in
  # the matching multi-region, and KMS key rings can never be deleted.
  description = "BigQuery dataset location. Must match the CMEK key location (var.region)."
  type        = string
  default     = "us-central1"
}

variable "alert_email" {
  description = "Email address to receive Brevo and Cloud Monitoring alerts"
  type        = string
}

variable "environment" {
  description = "Environment label applied to all resources (e.g., production, staging)"
  type        = string
  default     = "production"
}

variable "kms_key_rotation_period" {
  description = "Rotation period for the Cloud KMS CMEK key in seconds (90 days = 7776000s)"
  type        = string
  default     = "7776000s"
}

