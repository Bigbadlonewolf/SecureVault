# SecureVault – Intentional Checkov Skips

This document records every Checkov control that is intentionally skipped in the SecureVault Terraform configuration, along with the business justification, risk acceptance, and production remediation timeline.

## Status

- Last review date: 2026-07-03
- Terraform path: `terraform/`
- Active Checkov result: `0 failed, 1 skipped`

## Skipped controls

| Control | Resource | Justification | Risk acceptance | Production timeline |
|---|---|---|---|---|
| `CKV_GCP_62` | `google_storage_bucket.source_logs` | This bucket is the dedicated destination for access logs from `google_storage_bucket.source`. Requiring the log destination to log its own access would create an infinite logging loop and add cost without improving audit coverage. Access logs for the source bucket are already captured and retained. | Risk accepted for the demo environment because the log bucket itself is protected by CMEK, uniform bucket-level access, public-access prevention, and versioning. | If a separate security/audit log sink is required in production, route Cloud Audit Logs to a dedicated log bucket or Cloud Logging bucket instead of using Storage access logs. |

## Cost-vs-security note

The prompt that drove these changes (`fix-prompt.pdf`) requires production-grade controls (CMEK, VPC, Cloud NAT, access logging, deletion protection, least-privilege IAM labels, SARIF upload, secret environment variables, and Cloud Monitoring alerts). These controls intentionally exceed the original under-\$5/month demo budget. The `source_logs` skip above is the only remaining cost-control compromise needed to avoid a logging recursion issue.

## References

- `terraform/main.tf`
- `terraform/variables.tf`
- `.github/workflows/security-scan.yml`
- `adr/ADR-007-cost-model-vs-security-controls.md` (if present)
