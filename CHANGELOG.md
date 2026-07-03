# Changelog

## [Unreleased]

### Fixed
- Updated `actions/checkout` to `v4.2.2` and `actions/setup-python` to `v5.4.0` in `.github/workflows/ci.yml` to eliminate Node.js 20 deprecation annotations in the `python-tests` and `security-scan` jobs.
- Removed the `github.event_name == 'pull_request'` guard from the `terraform-plan` job so Terraform planning runs on both `push` and `pull_request` events in the canonical repository, resolving the previously reported 0s step duration.
- Ensured the `terraform-plan` job explicitly runs `terraform init`, `terraform validate`, and `terraform plan` from the `./terraform` working directory with visible stdout output.
- Fixed SCC finding-class routing: `main.py`, `remediator.py`, and `notifier.py` now derive the internal finding class through `classifier._extract_finding_class()`, which maps real SCC `category` values instead of relying on the generic `findingClass` enum.
- Rebuilt all test fixtures and `scripts/simulate_finding.py` to use the real SCC schema (`findingClass: MISCONFIGURATION` + a realistic `category`).
- Removed `OVER_PRIVILEGED_SA` from auto-remediation; it is now alert-only because SCC does not identify the specific excessive role.
- Implemented the missing Cloud Router + NAT resources in `terraform/main.tf` and pinned `vpc_connector_egress_settings = "ALL_TRAFFIC"` so function egress is actually routed through the VPC.
- Updated `FIXES.md` to match the implemented Terraform egress controls.
- Gated Terraform Plan in `.github/workflows/ci.yml` on the presence of `secrets.GCP_TERRAFORM_SA_KEY` so `fmt`, `init`, and `validate` still run when the credential is absent, while `plan` and the PR comment are skipped cleanly with an explicit log message.
- Consolidated CI/CD workflows: deleted redundant `.github/workflows/security-scan.yml` and zombie `.github/workflows/terraform-plan.yml`; all CI now runs through `.github/workflows/ci.yml`.
- Pinned CI tool versions for deterministic builds: `bandit==1.7.9`, `pip-audit==2.7.3`, `pytest==8.2.2`, `bridgecrewio/checkov-action@v12`, `trufflesecurity/trufflehog@v3.80.1`.
- Replaced the fake `verify` job in `.github/workflows/deploy.yml` with a real GitHub Checks API query that fails deployment if any check on the latest `main` commit is red.

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
