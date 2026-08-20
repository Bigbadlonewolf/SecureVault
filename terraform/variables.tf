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

variable "github_repository" {
  description = <<-EOT
    GitHub repository allowed to federate into the deployer service account,
    as "owner/name". This is the only thing standing between the deployer
    identity and any workflow on GitHub, so it is matched exactly rather than
    by prefix. Changing it changes who can deploy.
  EOT
  type        = string
  default     = "Bigbadlonewolf/SecureVault"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "github_repository must be exactly \"owner/name\"."
  }
}

variable "github_repository_id" {
  description = <<-EOT
    Immutable numeric ID of the GitHub repository allowed to federate.
    Repository names can be renamed or deleted and re-registered by someone
    else, so a name-only trust condition can be inherited by a stranger. The
    numeric ID cannot be reused. Find it with:
      gh api repos/<owner>/<name> --jq .id
  EOT
  type        = string
  default     = "1284525416"
}

variable "github_repository_owner_id" {
  description = <<-EOT
    Immutable numeric ID of the GitHub account that owns the repository.
    Find it with: gh api users/<owner> --jq .id
  EOT
  type        = string
  default     = "153934631"
}

variable "deployer_service_account_id" {
  description = "Account ID of the existing service account that GitHub Actions impersonates to run Terraform"
  type        = string
  default     = "securevault-deployer"
}

