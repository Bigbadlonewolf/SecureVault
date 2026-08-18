# SecureVault – Intentional Checkov Skips

This document records every Checkov control that is intentionally skipped in the SecureVault Terraform configuration, along with the business justification, risk acceptance, and production remediation timeline.

## Status

- Last review date: 2026-08-18
- Terraform path: `terraform/`
- Active Checkov result: `49 passed, 0 failed, 2 skipped`

## Skipped controls

Both skips are the same control, and both exist because GCS bucket access logging is unreachable on this project rather than merely inconvenient.

| Control | Resource | Justification | Risk acceptance | Production timeline |
| --- | --- | --- | --- | --- |
| `CKV_GCP_62` | `google_storage_bucket.source` | Access-log delivery requires granting `roles/storage.legacyBucketWriter` to `cloud-storage-analytics@google.com`, a principal outside this Cloud Identity customer. Domain Restricted Sharing (`constraints/iam.allowedPolicyMemberDomains`) refuses the binding at apply. An org-wide DRS exception for one legacy log mechanism is a worse trade than dropping the mechanism. | Accepted. The compensating control is the `DATA_READ`/`DATA_WRITE` audit config on `storage.googleapis.com`, which covers this bucket and — unlike a bucket-level `logging{}` block — cannot be disabled by someone who can edit bucket metadata. | Standing. Revisit only if the org drops DRS, and even then the audit config is the better mechanism. |
| `CKV_GCP_62` | `google_storage_bucket.source_logs` | Formerly the access-log destination. That mechanism is gone (see above), so the bucket is retained but empty with no writers. Self-logging an unwritten bucket serves no purpose. | Accepted. The bucket holds nothing and is still protected by CMEK, uniform bucket-level access, public-access prevention, and versioning. | Delete the bucket deliberately if the empty resource is unwanted. It was kept so the access-logging removal was non-destructive. |

## Cost-vs-security note

The v0.1.2 hardening pass added CMEK, VPC, Cloud NAT, access logging, deletion protection, least-privilege IAM labels, secret environment variables, and Cloud Monitoring alerts, knowingly exceeding the original under-\$5/month demo budget.

**Two items in that list are gone.** [ADR-009](adr/ADR-009-remove-vpc-connector-and-nat.md) removed the VPC and Cloud NAT, implemented 2026-07-28; `CKV2_GCP_18` (VPC network without a custom firewall rule) no longer applies because there is no VPC to flag. GCS bucket access logging was removed on 2026-08-17 as unreachable under Domain Restricted Sharing, and replaced by Cloud Audit Logs data-access logging on `storage.googleapis.com`, `secretmanager.googleapis.com` and `cloudkms.googleapis.com`. Neither skip here is a cost compromise; both are the same unreachable control.

## References

- `terraform/main.tf`
- `terraform/variables.tf`
- `.github/workflows/ci.yml`
- `adr/ADR-007-threat-model-and-trust-boundaries.md`
- `adr/ADR-008-cost-strategy-under-20-usd.md`
