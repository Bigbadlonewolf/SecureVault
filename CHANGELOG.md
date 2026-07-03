# Changelog

## [Unreleased]

### Fixed
- Updated `actions/checkout` to `v4.2.2` and `actions/setup-python` to `v5.4.0` in `.github/workflows/ci.yml` to eliminate Node.js 20 deprecation annotations in the `python-tests` and `security-scan` jobs.
- Removed the `github.event_name == 'pull_request'` guard from the `terraform-plan` job so Terraform planning runs on both `push` and `pull_request` events in the canonical repository, resolving the previously reported 0s step duration.
- Ensured the `terraform-plan` job explicitly runs `terraform init`, `terraform validate`, and `terraform plan` from the `./terraform` working directory with visible stdout output.

## [0.1.0] - 2026-07-02

### Added
- Initial SecureVault runtime security detection and response pipeline.
- Security Command Center (SCC) finding ingestion via Cloud Pub/Sub.
- Cloud Function `scc-processor` (Python 3.11, Gen 2) for classification and response.
- Severity-based decision engine: CRITICAL auto-remediate + alert, HIGH alert, MEDIUM log.
- Auto-remediation handlers for public bucket ACLs, open firewall rules, and over-privileged service accounts.
- Brevo email alerting with Secret Manager-backed API key storage.
- Firestore `remediation_log` collection for fast state lookups.
- BigQuery `securevault_analytics.findings_history` partitioned table for trend analysis.
- Cloud Monitoring dashboard and alert policy for Cloud Function error rate.
- Terraform IaC for all GCP resources with cost annotations.
- Context documentation: threat model, compliance mapping, cost analysis.
- Eight Architecture Decision Records (ADRs).
- GitHub Actions workflows for security scanning, Terraform planning, and manual deployment.
- Deployment guide, operations runbook, testing guide, and interview walkthrough.
- Hugo blog post for lanreoluokun.com.

### Security
- Zero secrets committed to source control.
- All Terraform and Python scans pass bandit, pip-audit, Checkov, and gcloud secrets scan.
