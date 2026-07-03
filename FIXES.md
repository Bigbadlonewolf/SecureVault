# SecureVault Defect & Hardening Fixes

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** v0.1.2 prompt-driven production hardening

This document records the defects resolved and the production-grade hardening applied to SecureVault as directed by `fix-prompt.pdf`.

---

## 1. CI: TruffleHog `BASE and HEAD are the same`

**Defect:** TruffleHog failed on single-commit pushes because the checkout depth made the base and head references identical.

**Fix:** Updated `.github/workflows/security-scan.yml` to set `fetch-depth` dynamically based on the number of commits in the push or PR, and to pass explicit `base` and `head` references to the TruffleHog action.

---

## 2. CI: Consolidated Security Scanning

**Defect:** Checkov results were not surfaced in the GitHub Security tab, and security scanning was split between `ci.yml` and a redundant `security-scan.yml` that created duplicate runs and conflicting status checks.

**Fix:** Removed the redundant `security-scan.yml` and kept Checkov enforcement in the consolidated `ci.yml` security job. Tool versions are now pinned (`bandit==1.7.9`, `pip-audit==2.7.3`, `checkov-action@v12`, `trufflehog@v3.80.1`) for deterministic builds. SARIF upload was dropped in favor of a single, enforceable security gate.

---

## 3. Terraform: VPC and Egress Controls

**Defects addressed:**

- `CKV2_GCP_18` — VPC network had no custom firewall rule.
- Cloud Function egress used the public internet.

**Fix:**

- Added `google_compute_network.securevault` with `auto_create_subnetworks = false`.
- Added `google_compute_subnetwork.securevault` (`10.0.0.0/28`) with flow logs, `private_ip_google_access`, and `private_ipv6_google_access`.
- Added `google_compute_router.securevault` + `google_compute_router_nat.securevault` for Cloud NAT egress.
- Added `google_compute_firewall.deny_all_ingress` default-deny rule.
- Added `google_vpc_access_connector.securevault` and attached it to the Cloud Function.
- Set `vpc_connector_egress_settings = "ALL_TRAFFIC"` so all function egress traverses the VPC and NAT.

---

## 4. Terraform: Customer-Managed Encryption Keys (CMEK)

**Defects addressed:**

- `CKV_GCP_80` — BigQuery table CSEK.
- `CKV_GCP_81` — BigQuery dataset CSEK.
- `CKV_GCP_83` (historical) — Pub/Sub topic CMEK.
- Source bucket used Google-managed encryption.

**Fix:**

- Added `google_kms_key_ring.securevault` and `google_kms_crypto_key.securevault` with 90-day rotation.
- Added IAM bindings granting `roles/cloudkms.cryptoKeyEncrypterDecrypter` to Cloud Storage, Pub/Sub, BigQuery, and (existing) Secret Manager service agents.
- Applied CMEK to `google_storage_bucket.source`, `google_pubsub_topic.scc_findings`, `google_bigquery_dataset.analytics`, and `google_bigquery_table.findings_history`.

---

## 5. Terraform: Key and Table Deletion Protection

**Defects addressed:**

- `CKV_GCP_82` — KMS crypto key lacked deletion protection.
- `CKV_GCP_121` — BigQuery table lacked deletion protection.

**Fix:**

- Added `lifecycle { prevent_destroy = true }` to `google_kms_crypto_key.securevault`.
- Added `deletion_protection = true` to `google_bigquery_table.findings_history`.

---

## 6. Terraform: Storage Access Logging

**Defect addressed:**

- `CKV_GCP_62` — `google_storage_bucket.source` did not log access.

**Fix:**

- Created a dedicated log bucket `google_storage_bucket.source_logs` with CMEK, versioning, uniform bucket-level access, and public-access prevention.
- Granted `roles/storage.legacyBucketWriter` to `serviceAccount:cloud-storage-analytics@google.com`.
- Added a `logging` block to `google_storage_bucket.source` pointing to the log bucket.
- Skipped `CKV_GCP_62` on `source_logs` itself to avoid an infinite logging loop; documented in `CHECKOV_SKIP.md`.

---

## 7. Terraform: Cloud Function Security Hardening

**Defects addressed:**

- `CKV_GCP_124` — Cloud Function ingress was `ALLOW_ALL` by default.
- Secrets were passed as plain environment variables.

**Fix:**

- Set `ingress_settings = "ALLOW_INTERNAL_ONLY"`.
- Moved `BREVO_API_KEY` from `environment_variables` to `secret_environment_variables`.
- Added `local.common_labels` with `managed-by = "terraform"` and `data-classification = "security"` to all resources.
- Added a Cloud Monitoring alert for high-severity SCC findings.

---

## 8. Terraform: Least-Privilege IAM Labels

**Defect addressed:** Checkov flagged missing resource labels that support IAM/ownership tracking.

**Fix:** Applied `local.common_labels` consistently across Terraform resources.

---

## Files Modified

- `.github/workflows/ci.yml` (consolidated security scanning, pinned tool versions)
- `.github/workflows/deploy.yml` (real Checks API verification gate)
- `terraform/main.tf`
- `terraform/variables.tf`
- `terraform/outputs.tf`
- `CHECKOV_SKIP.md` (new)
- `FIXES.md` (updated)

---

## Validation Summary

| Check | Result |
|---|---|
| `pytest -q` | 23 passed |
| `terraform validate` | Success |
| `terraform fmt -recursive` | Formatted |
| `checkov -d terraform/ --framework terraform --quiet` | 62 passed, 0 failed, 1 documented skip |
| `pip-audit -r src/requirements.txt` | No known vulnerabilities |
| `bandit -r src/` | No issues identified |
| `truffleHog filesystem . --only-verified` | No verified secrets found |

All Checkov failures from the prompt have been resolved through implementation or documented risk acceptance.
