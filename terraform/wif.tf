# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

#-------------------------------------------------------------------------------
# Workload Identity Federation for GitHub Actions
#
# Replaces the exportable service account JSON key that deploy.yml expected in
# secrets.GCP_TERRAFORM_SA_KEY. GitHub mints a short-lived OIDC token per job,
# STS exchanges it for a federated token, and IAM Credentials mints an access
# token for the deployer service account. Nothing long-lived is stored in the
# repository, so there is no credential to leak, rotate, or forget to revoke.
#
# The deployer service account is deliberately NOT scoped down here. Terraform
# in this repository creates a KMS key ring, a custom IAM role, project IAM
# bindings and four service accounts, so it genuinely requires roleAdmin,
# projectIamAdmin, serviceAccountAdmin and cloudkms.admin. Trimming those would
# break the apply rather than harden it. The security win is removing the
# exportable key and constraining who may assume the identity, not shortening
# the role list.
#
# It is also not managed by this configuration: the account predates the state
# file and is read through a data source. Importing it would make Terraform the
# owner of the credentials it authenticates with, which fails closed in an
# unrecoverable way if an apply ever revokes them mid-run.
#-------------------------------------------------------------------------------

# WIF's two APIs are enabled by their own resource rather than being added to
# google_project_service.services in main.tf. Adding for_each keys there marks
# that resource as having pending changes, which defers the two service-agent
# data sources that depend_on it, which in turn forces replacement of the
# CMEK bindings for the GCS and BigQuery service agents. Those bindings are
# what let GCS read the CMEK key that now encrypts the Terraform state bucket,
# so churning them mid-apply risks Terraform losing the ability to write its
# own state. Keeping the change out of that resource avoids the whole chain.
resource "google_project_service" "wif" {
  for_each = toset([
    # Exchanges the GitHub OIDC token for a federated token.
    "sts.googleapis.com",
    # Mints the deployer access token once the exchange succeeds.
    "iamcredentials.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

data "google_project" "this" {
  project_id = var.project_id
}

data "google_service_account" "deployer" {
  account_id = var.deployer_service_account_id
  project    = var.project_id
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "Federated identities for SecureVault CI/CD"

  depends_on = [google_project_service.wif]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub OIDC"

  # Without an attribute_condition this provider would accept a token from any
  # workflow in any repository on GitHub. The condition is the perimeter, and
  # it is an exact match on the full owner/name -- a prefix or suffix match
  # would admit a lookalike repository created by anyone.
  attribute_condition = "assertion.repository == \"${var.github_repository}\""

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.ref"              = "assertion.ref"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Allow only workflows in the named repository to impersonate the deployer.
# The principalSet is scoped by attribute.repository rather than by the pool
# root: binding the pool itself would let every identity the pool ever federates
# assume this account.
resource "google_service_account_iam_member" "github_deployer_impersonation" {
  service_account_id = data.google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

output "workload_identity_provider" {
  description = "Full provider resource name for google-github-actions/auth"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "deployer_service_account_email" {
  description = "Service account GitHub Actions impersonates via WIF"
  value       = data.google_service_account.deployer.email
}

output "project_number" {
  description = "Project number, used to construct federated principal names"
  value       = data.google_project.this.number
}
