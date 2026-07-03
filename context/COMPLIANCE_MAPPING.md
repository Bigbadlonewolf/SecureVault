# SecureVault Compliance Mapping

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

SecureVault is designed to satisfy detective, responsive, and audit controls across three common security frameworks. This document maps each relevant control to the SecureVault implementation and the evidence location an assessor can inspect.

## Framework Summary

| Framework | Controls Mapped |
|---|---|
| NIST SP 800-53 Rev 5 | SI-4, IR-4, AU-6, CM-6 |
| PCI DSS v4.0 | Requirement 10 (Logging), Requirement 11 (Vulnerability Management) |
| SOC 2 (2017 Trust Services Criteria) | CC6.1, CC7.2 |

## Control Mapping Table

| Control / Requirement | SecureVault Implementation | Evidence Location |
|---|---|---|
| **NIST SP 800-53 Rev 5 — SI-4**<br>Information System Monitoring | SCC findings are consumed continuously via Pub/Sub. The Cloud Function classifies every finding and routes it to remediation, alerting, or logging. A Cloud Monitoring dashboard tracks findings by severity, remediation outcomes, and alert delivery. | [`terraform/main.tf`](../terraform/main.tf) (Pub/Sub, Function, Monitoring)<br>`src/processors/classifier.py`<br>Cloud Monitoring Dashboard: `SecureVault Dashboard` |
| **NIST SP 800-53 Rev 5 — IR-4**<br>Incident Handling | The response matrix defines graded actions: CRITICAL mapped findings are auto-remediated and alerted; unmapped CRITICAL findings are alerted only; HIGH findings are alerted immediately; MEDIUM findings are logged for trend review. | [`adr/ADR-004-severity-response-matrix.md`](../adr/ADR-004-severity-response-matrix.md)<br>`src/processors/remediator.py`<br>[`context/THREAT_MODEL.md`](THREAT_MODEL.md) |
| **NIST SP 800-53 Rev 5 — AU-6**<br>Audit Review | Every processed finding is written to Firestore (`remediation_log`) and BigQuery (`findings_history`), with a date-partitioned table supporting trend queries. Cloud Audit Logs capture all IAM and API activity. | [`terraform/main.tf`](../terraform/main.tf) (Firestore, BigQuery)<br>`src/storage/firestore_client.py`<br>`src/storage/bigquery_client.py`<br>Cloud Audit Logs |
| **NIST SP 800-53 Rev 5 — CM-6**<br>Configuration Settings | Auto-remediation returns affected resources to a hardened baseline: public bucket ACLs are removed, open firewall rules are disabled, and over-privileged service accounts are trimmed. All infrastructure is defined in Terraform and reapplied through plan/apply gates. | [`terraform/main.tf`](../terraform/main.tf)<br>`src/processors/remediator.py`<br>`.github/workflows/terraform-plan.yml` |
| **PCI DSS v4.0 — Req. 10**<br>Logging and Monitoring | SecureVault produces a durable, timestamped audit trail across Firestore, BigQuery, and Cloud Audit Logs. Logs include finding ID, resource, severity, action, status, error, and project. Access to logs is governed by IAM. | [`SECURITY.md`](../SECURITY.md)<br>`src/storage/*`<br>[`terraform/bigquery_schema.json`](../terraform/bigquery_schema.json)<br>Cloud Audit Logs |
| **PCI DSS v4.0 — Req. 11**<br>Vulnerability & Misconfiguration Management | SCC misconfiguration findings (public storage, open firewalls, over-privileged identities) are ingested, classified, and either remediated automatically or escalated via alert for human review. | [`adr/ADR-001-scc-over-cspm.md`](../adr/ADR-001-scc-over-cspm.md)<br>`src/processors/classifier.py`<br>`src/processors/remediator.py` |
| **SOC 2 — CC6.1**<br>Logical Access | The Cloud Function runs under a dedicated service account with a custom least-privilege role. The Pub/Sub topic restricts publishing to the SCC notification service account. Secrets are stored in Secret Manager, not code. | [`terraform/main.tf`](../terraform/main.tf) (service account, IAM bindings, Secret Manager)<br>[`SECURITY.md`](../SECURITY.md)<br>[`context/THREAT_MODEL.md`](THREAT_MODEL.md) |
| **SOC 2 — CC7.2**<br>System Monitoring | Continuous monitoring of security findings, real-time classification, alert policies for function errors, and dashboards provide visibility into the security posture of the environment. | [`terraform/main.tf`](../terraform/main.tf) (dashboard, alert policy)<br>`src/processors/classifier.py`<br>Cloud Monitoring Dashboard |

## How Assessor's Can Verify

1. **Terraform plan review** — Run `terraform plan` and inspect IAM bindings, custom roles, and resource configurations.
2. **Code review** — Inspect `src/processors/` for classification, remediation, and notification logic.
3. **Log inspection** — Query `securevault_analytics.findings_history` in BigQuery and the `remediation_log` collection in Firestore.
4. **IAM audit** — Review Cloud Audit Logs for `SetIamPolicy` calls on the Pub/Sub topic and service account usage.
5. **CI evidence** — Check GitHub Actions runs for `bandit`, `pip-audit`, `Checkov`, and Terraform plan results.

## Gaps & Phase 2 Enhancements

- **CC6.1 / CM-6:** Periodic automated configuration drift detection (independent of SCC) is not yet implemented.
- **AU-6 / Req. 10:** Log retention policies are inherited from GCP defaults; explicit lifecycle rules will be added in Phase 2.
- **IR-4:** Integration with a SOAR/ticketing tool (ServiceNow, Jira) is not included in v0.1.0.

These gaps are tracked in [`README.md`](../README.md) under Known Limitations & Phase 2.
