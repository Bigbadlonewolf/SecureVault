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
# unrecoverable way if an apply ever revokes them mid-run. Its roles are
# granted out of band for the same reason, including the one this file made
# necessary -- Terraform now manages a pool the deployer must be able to read:
#
#   gcloud projects add-iam-policy-binding securevault-demo \
#     --member="serviceAccount:securevault-deployer@securevault-demo.iam.gserviceaccount.com" \
#     --role="roles/iam.workloadIdentityPoolAdmin"
#
# Without it, plan fails on refresh with
# "Permission 'iam.workloadIdentityPools.get' denied".
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

  # This condition is the entire perimeter. Without it the provider accepts a
  # token from any workflow in any repository on GitHub.
  #
  # It pins two independent things:
  #
  # The immutable numeric IDs, because GitHub repository and account names are
  # re-usable. Rename or delete this repo and the string
  # "Bigbadlonewolf/SecureVault" becomes claimable by a stranger, who would
  # then satisfy a name-only condition and be able to impersonate a deployer
  # holding roleAdmin, projectIamAdmin and cloudkms.admin. Numeric IDs are
  # never reissued.
  #
  # The exact sub claims, which restrict *which jobs* in this repository may
  # federate rather than admitting all of them. GitHub's sub is
  # "repo:<owner>/<name>:<context>", where the context is the git ref for an
  # ordinary job and the environment name for a job that declares one.
  # deploy.yml declares `environment: production` and ci.yml does not, so the
  # two workflows present different subs and both have to be named.
  #
  # Pull request subs are deliberately absent. For a same-repository pull
  # request GitHub runs the workflow file as it exists on the PR head, so
  # admitting "repo:<owner>/<name>:pull_request" would let anyone who can open
  # a PR rewrite the workflow and read the deployer's access token. CI plans on
  # pull requests run without credentials instead; see ci.yml.
  #
  # Two things about how this is written, both forced by CKV_GCP_125:
  #
  # The inner literals are single-quoted. CEL accepts either quote style, but
  # escaped double quotes survive HCL parsing as a literal backslash-quote and
  # the check matches on `== "` or `== '` with nothing between, so a
  # \"-escaped condition fails no matter how tightly it is actually scoped.
  #
  # The value is spelled out rather than interpolated from the variables above.
  # The check reads the unrendered attribute and resolves neither var nor local
  # references, so any interpolated form fails. That is a scanner limitation,
  # but a literal perimeter is worth having on its own terms: this is the one
  # line that decides who may act as the deployer, and it should be readable
  # and greppable without resolving indirection. The precondition below is what
  # stops it drifting away from the variables.
  attribute_condition = "assertion.repository_owner_id == '153934631' && assertion.repository_id == '1284525416' && (assertion.sub == 'repo:Bigbadlonewolf/SecureVault:ref:refs/heads/main' || assertion.sub == 'repo:Bigbadlonewolf/SecureVault:environment:production')"

  lifecycle {
    precondition {
      condition = (
        var.github_repository == "Bigbadlonewolf/SecureVault" &&
        var.github_repository_id == "1284525416" &&
        var.github_repository_owner_id == "153934631"
      )
      error_message = <<-EOT
        attribute_condition on this resource is a hardcoded literal, because
        CKV_GCP_125 cannot resolve interpolated values. The repository
        variables no longer match it, so the literal and the principalSet
        binding now describe different repositories. Update the
        attribute_condition string to match the new variables.
      EOT
    }
  }

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
