variable "project_id" {
  description = "GCP project ID where SecureVault will be deployed"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "alert_email" {
  description = "Email address to receive security alerts"
  type        = string
}

variable "alert_from_email" {
  description = "From email address for alert emails"
  type        = string
  default     = "security-alerts@securevault.dev"
}

variable "sendgrid_api_key" {
  description = "SendGrid/Brevo API key for sending alert emails"
  type        = string
  sensitive   = true
}
