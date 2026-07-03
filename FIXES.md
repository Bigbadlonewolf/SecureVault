# SecureVault Defect Fixes

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** v0.1.1 defect-remediation pass

This document lists the defects identified in the SecureVault GCP portfolio project and the exact changes made to resolve them.

---

## 1. CKV_GCP_124 — Cloud Function Ingress Settings

**Defect:** `google_cloudfunctions2_function.scc_processor` had no `ingress_settings` defined, defaulting to `ALLOW_ALL`.

**Fix:** Added `ingress_settings = "ALLOW_INTERNAL_ONLY"` to the `service_config` block in `terraform/main.tf`.

**Rationale:** The function is triggered exclusively by an internal Pub/Sub event. Allowing ingress from all sources is unnecessary and expands the attack surface. `ALLOW_INTERNAL_ONLY` permits only internal Google Cloud services (including Pub/Sub/Eventarc) to invoke the function.

---

## 2. Excessive Checkov Skip Comments

**Defect:** Six `checkov:skip` comments in `terraform/main.tf` had weak or cost-only justifications.

**Fix:** Kept all six skips because each control would either break the under-$5 cost model or provide negligible security value for this non-sensitive data, but strengthened every inline comment to include:

- The specific risk being accepted.
- A statement that the risk is accepted per the project threat model.
- A reference to `context/THREAT_MODEL.md` and `adr/ADR-007-threat-model-and-trust-boundaries.md`.

**Skips retained with documented risk acceptance:**

| Skip | Resource | Justification |
|---|---|---|
| `CKV_GCP_62` | `google_storage_bucket.source` | Source bucket stores only ephemeral, non-sensitive build zips. Access logging would add a log bucket and cost for low security value. |
| `CKV_GCP_78` | `google_storage_bucket.source` | Source zips are rebuild artifacts; old versions provide no security value. Versioning would add storage cost. |
| `CKV_GCP_80` | `google_bigquery_table.findings_history` | Default GCP-managed encryption is sufficient for analytics data; CMEK key-management cost is not justified. |
| `CKV_GCP_81` | `google_bigquery_dataset.analytics` | Same as CKV_GCP_80: CMEK is not cost-justified for this low-sensitivity dataset. |
| `CKV_GCP_83` | `google_pubsub_topic.scc_findings` | Topic holds transient SCC notifications only; CMEK would require a Cloud KMS key and exceed the cost target. |
| `CKV_GCP_121` | `google_bigquery_table.findings_history` | Deletion protection disabled for cost-controlled cleanup. Data is replicated to Firestore and Cloud Audit Logs. |

**Verification:**

```bash
checkov -d terraform/ --framework terraform --quiet
# terraform scan results:
# Passed checks: 39, Failed checks: 0, Skipped checks: 6
```

---

## 3. Missing `__init__.py` Files

**Defect:** Python package directories lacked `__init__.py` files with project attribution headers.

**Fix:** The repository had already been restructured to the `src/scc_processor/` package layout. Confirmed that all four package directories contain minimal `__init__.py` files with the standard attribution header:

- `src/scc_processor/__init__.py`
- `src/scc_processor/processors/__init__.py`
- `src/scc_processor/storage/__init__.py`
- `src/scc_processor/utils/__init__.py`

Each file contains only the SecureVault attribution header and license.

---

## 4. Mislabeled Pub/Sub IAM "Deny" Resource

**Defect:** `google_pubsub_topic_iam_member.deny_default_compute` granted `roles/pubsub.viewer` to the default compute service account. This did not deny access and could be confused with a real security control.

**Fix:** Removed the resource entirely from `terraform/main.tf`.

**Rationale:** The topic is secure by default because only the SCC notification service account is explicitly granted `roles/pubsub.publisher`. No other principal has any access unless added elsewhere. A fake "deny" resource added confusion without improving security.

---

## 5. Placeholder Secret Manager Version

**Defect:** `google_secret_manager_secret_version.brevo_api_key_version` had `enabled = false` and placeholder data `"CHANGEME-SET-BREVO-API-KEY"`. This caused the Cloud Function to fail at runtime when reading the `latest` version.

**Fix:**

- Removed `google_secret_manager_secret_version.brevo_api_key_version` from `terraform/main.tf`.
- Updated `docs/DEPLOYMENT_GUIDE.md` Step 3 to instruct the operator to create the first real secret version with `gcloud secrets versions add brevo-api-key` **after** `terraform apply`.
- Removed references to disabling a placeholder version from the troubleshooting section.

**Rationale:** Secret values should never be in Terraform state or source control. Creating the version manually after infrastructure provisioning keeps the secret out of state while ensuring the function reads an enabled, real key.

---

## 6. Incorrect Eventarc Service Account in `event_trigger`

**Defect:** The `event_trigger` block used `service_account_email = google_service_account.scc_processor.email`, which is the function runtime service account. Pub/Sub triggers are invoked by the Eventarc control plane, not the function runtime identity.

**Fix:** Removed `service_account_email` from the `event_trigger` block in `terraform/main.tf`.

**Rationale:** When omitted, GCP uses the appropriate Eventarc-managed trigger identity. Setting the function runtime SA in this field is incorrect and can cause trigger creation or invocation failures.

---

## 7. `pip-audit` Requirements Path

**Defect:** `.github/workflows/security-scan.yml` references `src/requirements.txt` for `pip-audit`.

**Fix:** Verified that `src/requirements.txt` exists at that path. No file-path change was required.

---

## Files Modified

- `terraform/main.tf`
- `docs/DEPLOYMENT_GUIDE.md`
- `.github/workflows/security-scan.yml` (formatting/manual-dispatch cleanup from prior remediation; path verified)
- `FIXES.md` (new)

## Files Output (Copy-Paste-Ready)

- `terraform/main.tf` — full corrected file
- `src/scc_processor/__init__.py`
- `src/scc_processor/processors/__init__.py`
- `src/scc_processor/storage/__init__.py`
- `src/scc_processor/utils/__init__.py`
- `.github/workflows/security-scan.yml`
- `FIXES.md`

---

## Validation Summary

| Check | Result |
|---|---|
| `pytest -q` | 22 passed |
| `terraform validate` | Success |
| `checkov -d terraform/ --framework terraform --quiet` | 39 passed, 0 failed, 6 documented skips |
| `pip-audit -r src/requirements.txt --desc` | No known vulnerabilities |
| `bandit -r src/ scripts/ -ll` | No issues identified |

All defects resolved without changing the architecture or adding new features.
