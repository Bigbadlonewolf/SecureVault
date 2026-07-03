# Security Scan Report

> **Architect:** Lanre Oluokun | **Implementation:** AI-assisted | **Generated:** 2026-07-03

## Scanners Executed

| Scanner | Version | Command | Status |
|---|---|---|---|
| bandit | 1.9.4 | `bandit -r src/ -ll -f json -o bandit-report.json` | ✅ Pass |
| pip-audit | 2.10.1 | `pip-audit -r src/requirements.txt --desc` | ✅ Pass |
| Checkov | 3.1.47 | `checkov --directory terraform/ --framework terraform --quiet --compact` | ✅ Pass |
| truffleHog | 3.95.8 | `trufflehog filesystem src/ --only-verified` | ✅ Pass |
| gcloud secrets scan | N/A | `gcloud secrets scan --source=src/` | ⚠️ Not available in this gcloud version |
| Terraform validate | 1.15.7 | `terraform validate` | ✅ Pass |

## Findings and Resolutions

### bandit
- **Initial finding:** B110 (`try_except_pass`) in `src/utils/logger.py` when Cloud Logging client initialization fails.
- **Resolution:** Replaced bare `pass` with a fallback warning log to stderr.
- **Final result:** 0 issues.

### pip-audit
- **Initial finding:** `requests==2.31.0` had three known CVEs (CVE-2024-35195, CVE-2024-47081, CVE-2026-25645).
- **Resolution:** Upgraded to `requests==2.33.0` in `src/requirements.txt` and re-ran unit tests.
- **Final result:** No known vulnerabilities.

### Checkov
- **Initial findings:** 6 Terraform checks failed, all related to CSEK encryption or optional data-protection features:
  - `CKV_GCP_83` — Pub/Sub topic CSEK
  - `CKV_GCP_62` — Cloud Storage access logging
  - `CKV_GCP_78` — Cloud Storage versioning
  - `CKV_GCP_81` — BigQuery dataset CSEK
  - `CKV_GCP_80` — BigQuery table CSEK
  - `CKV_GCP_121` — BigQuery table deletion protection
- **Resolution:** Added `checkov:skip=` comments with architectural justification. Default GCP-managed encryption is used intentionally to stay within the $5/month target; ephemeral source artifacts and analytics data do not warrant CSEK key-management cost. The source bucket holds only Cloud Function zip files, so versioning and access logging are disabled as cost optimizations.
- **Final result:** 0 failed checks (6 skipped with documented justification).

### truffleHog
- **Finding:** None.
- **Result:** 0 verified secrets, 0 unverified secrets.

### Terraform
- **Validation:** `terraform validate` succeeded.
- **Plan:** `terraform plan` requires Application Default Credentials (ADC). The configuration is syntactically valid and ready for planning once ADC is available in the deployment environment. Run `gcloud auth application-default login` to generate ADC before planning/applying.

## Intentional Exclusions

| Resource | Checkov ID | Justification |
|---|---|---|
| `google_pubsub_topic.scc_findings` | CKV_GCP_83 | Transient SCC notifications use GCP-managed encryption; CSEK is not cost-justified under the $5/month target. |
| `google_storage_bucket.source` | CKV_GCP_62 | Access logging disabled; bucket stores only ephemeral Cloud Function source zips. |
| `google_storage_bucket.source` | CKV_GCP_78 | Versioning disabled; source zips are rebuild artifacts with no retention value. |
| `google_bigquery_dataset.analytics` | CKV_GCP_81 | Default GCP-managed encryption is sufficient for analytics. |
| `google_bigquery_table.findings_history` | CKV_GCP_80 | Default GCP-managed encryption is sufficient for findings history. |
| `google_bigquery_table.findings_history` | CKV_GCP_121 | Deletion protection disabled to allow cost-controlled cleanup; durable audit trail exists in Firestore and Cloud Audit Logs. |

## Sign-off

All available scanners pass. The remaining action before deployment is to authenticate the GCP environment and run `terraform plan`.
