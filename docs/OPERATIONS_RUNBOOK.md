# SecureVault Operations Runbook

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

This runbook provides step-by-step response procedures for common operational issues. It is designed for a 2 a.m. incident response scenario where the responder has GCP console or `gcloud` access.

For initial deployment steps, see [`docs/DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md). For testing procedures, see [`docs/TESTING.md`](TESTING.md).

---

## 1. Pipeline Stopped Processing Findings

### Indicators

- No new entries in the `remediation_log` Firestore collection.
- No new rows in `securevault_analytics.findings_history`.
- Cloud Monitoring dashboard shows flatlines for findings processed.
- SCC notifications are configured, but findings are not being acted upon.

### Diagnostic Steps

1. **Check Cloud Function errors:**

   ```bash
   gcloud functions logs read scc-processor --limit=100
   ```

   Look for repeated `500` errors, import failures, or timeout messages.

2. **Check the Cloud Monitoring alert policy:**

   - Open **Monitoring > Alerting** in the GCP console.
   - Look for a firing alert named **SecureVault Function Error Rate > 5%**.

3. **Check Pub/Sub lag:**

   ```bash
   gcloud pubsub subscriptions list --topic=projects/YOUR_PROJECT_ID/topics/scc-findings
   gcloud pubsub subscriptions describe SUBSCRIPTION_NAME --format="value(name, ackDeadlineSeconds, messageRetentionDuration, deadLetterPolicy)"
   ```

   High unacked message counts indicate the function is not keeping up or is crashing.

4. **Check function health and metrics:**

   ```bash
   gcloud functions describe scc-processor --region=us-central1 --format="value(status, serviceConfig.availableMemory, serviceConfig.timeoutSeconds)"
   ```

### Common Causes & Fixes

| Cause | Fix |
|---|---|
| Function crashed on invalid finding | Review stack trace in logs; add defensive parsing if needed. |
| Missing IAM permission | Verify `roles/datastore.user`, `roles/bigquery.dataEditor`, `roles/secretmanager.secretAccessor`, and the custom remediation role are attached to `scc-processor@`. |
| Secret Manager key inaccessible | Confirm the Brevo secret exists and the placeholder version is disabled. |
| Cold-start storm causing timeouts | Increase `timeout_seconds` temporarily; check if dependencies are bloated. |
| Pub/Sub retry exhaustion | Inspect dead-letter topic; republish messages after fixing the root cause. |

### Escalation

If the root cause is not clear within 15 minutes:

1. Pause auto-remediation by redeploying with `auto_remediate: []` in `src/config.yaml` (see Section 3).
2. Notify the on-call security engineer via the alert email.
3. Open a post-incident review issue referencing Cloud Logging logs.

---

## 2. Brevo Alerts Not Sending

### Indicators

- Function logs show findings processed but no email received.
- Cloud Logging shows Brevo errors such as `401 Unauthorized`, `403 Forbidden`, or `429 Too Many Requests`.

### Diagnostic Steps

1. **Check Secret Manager key:**

   ```bash
   gcloud secrets versions list brevo-api-key
   ```

   - Exactly one version should be enabled.
   - The placeholder version should be disabled.

2. **Verify secret access:**

   ```bash
   gcloud secrets get-iam-policy brevo-api-key
   ```

   Ensure `scc-processor@YOUR_PROJECT_ID.iam.gserviceaccount.com` has `roles/secretmanager.secretAccessor`.

3. **Check Brevo dashboard:**

   - Log in to [Brevo](https://app.brevo.com/).
   - Confirm the API key is active.
   - Check the daily send limit (300 emails/day on the free tier).
   - Review suppressed or bounced addresses.

4. **Check Cloud Logging for Brevo responses:**

   ```bash
   gcloud logging read "jsonPayload.event=\"brevo_alert_failed\" OR jsonPayload.event=\"brevo_alert_sent\"" --limit=50
   ```

### Common Causes & Fixes

| Cause | Fix |
|---|---|
| Placeholder secret still enabled | Add the real Brevo key and disable the placeholder version. |
| API key revoked in Brevo | Generate a new key and add it as a new Secret Manager version. |
| Free tier daily limit reached | Wait for reset or upgrade Brevo plan; function will continue logging. |
| Alert email blocked or invalid | Update `alert_email` in `terraform.tfvars` and re-run `terraform apply`. |
| Brevo API outage | Function degrades gracefully; monitor [Brevo status](https://status.brevo.com/). |

---

## 3. Auto-Remediation Too Aggressive

### Indicators

- Production resources were modified unexpectedly (bucket ACLs removed, firewall rules disabled, IAM roles trimmed).
- Logs show `action=remediate` for finding classes that should be human-reviewed.
- Stakeholders report false-positive-driven remediation.

### Immediate Action

1. Open `src/config.yaml`.
2. Locate the `response_matrix` section.

### Modify the Response Matrix

The safest change is to remove a finding class from the `CRITICAL.auto_remediate` list. For example, to stop auto-remediating open firewall rules:

```yaml
response_matrix:
  CRITICAL:
    auto_remediate:
      - PUBLIC_BUCKET_ACL
      # - OPEN_FIREWALL   # now alerts only
    default_action: alert_only
  HIGH:
    action: alert
  MEDIUM:
    action: log_digest
```

Note that `OVER_PRIVILEGED_SA` is alert-only by design and is never in the
`auto_remediate` list.

To disable all auto-remediation temporarily:

```yaml
response_matrix:
  CRITICAL:
    auto_remediate: []      # nothing is auto-remediated
    default_action: alert_only
```

### Re-deploy

After editing `config.yaml`, redeploy the function:

```bash
cd terraform
terraform apply
```

### Follow-Up

- Document the change and the business justification.
- Review [`adr/ADR-004-severity-response-matrix.md`](../adr/ADR-004-severity-response-matrix.md).
- Update unit tests in `tests/test_remediator.py` if the set of mapped classes changes.

---

## 4. Cost Spike

### Indicators

- GCP billing alert fires at $15/month.
- A single service shows unexpected growth in the billing breakdown.

### Diagnostic Steps

1. **Identify the service:**

   - Open **Billing > Reports** in the GCP console.
   - Group by service and filter by project.

2. **Common service-specific checks:**

   **Cloud Functions:**

   ```bash
   gcloud functions describe scc-processor --region=us-central1 --format="value(serviceConfig.availableMemory, serviceConfig.timeoutSeconds, serviceConfig.maxInstanceCount)"
   ```

   - Look for invocation count spikes in Cloud Monitoring.
   - Check whether retries are driving repeated executions.

   **BigQuery:**

   ```bash
   bq query --use_legacy_sql=false 'SELECT * FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY) ORDER BY total_bytes_processed DESC LIMIT 20'
   ```

   - Look for full-table scans or unpartitioned queries.

   **Pub/Sub:**

   - Verify message retention is still 1 day (default is 7 days).
   - Confirm subscription backlog is not growing indefinitely.

   **Firestore:**

   - Review indexes; hot indexes can increase cost unexpectedly.
   - Confirm only one document is written per finding.

### Cost Optimization Measures

| Service | Quick Fix |
|---|---|
| Cloud Functions | Lower `max_instance_count`; reduce memory only if latency remains acceptable. |
| BigQuery | Add `WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)` to all trend queries. |
| Pub/Sub | Confirm `message_retention_duration = "86400s"` in Terraform. |
| Firestore | Switch from per-finding writes to hourly batch writes if volume exceeds 10,000 findings/month. |

For long-term scaling guidance, see [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md) and [`adr/ADR-008-cost-strategy-under-20-usd.md`](../adr/ADR-008-cost-strategy-under-20-usd.md).

---

## 5. False Positive Flood

### Indicators

- A specific finding class is generating a high volume of MEDIUM or HIGH alerts.
- BigQuery trend queries show a sudden spike from a known noisy detector.
- The team is ignoring SecureVault alerts because of noise.

### Diagnostic Steps

1. Query `securevault_analytics.findings_history` to identify the noisy finding class:

   ```sql
   SELECT
     finding_class,
     severity,
     COUNT(*) AS count
   FROM `YOUR_PROJECT_ID.securevault_analytics.findings_history`
   WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
   GROUP BY finding_class, severity
   ORDER BY count DESC;
   ```

2. Check whether the class should be elevated, suppressed, or reclassified.

### Adjust Severity Classifier Overrides

Severity overrides live in the `severity_overrides` list in `src/config.yaml`. A class on that list is always elevated to CRITICAL regardless of the severity SCC assigns. To stop a noisy class from being elevated, remove it from the list so its native SCC severity applies:

```yaml
# Finding classes that should always be elevated to CRITICAL regardless of SCC severity.
severity_overrides:
  - PUBLIC_BUCKET_ACL
  - OPEN_FIREWALL
  # - OVER_PRIVILEGED_SA   # removed: handled at native SCC severity
```

A class that is not elevated and arrives as MEDIUM is logged for digest by default (`response_matrix.MEDIUM.action: log_digest`), so no further change is needed to keep it out of the alert path.

### Important Safeguards

- Do not override CRITICAL security findings (e.g., public buckets) to MEDIUM without documented approval.
- Add a unit test in `tests/test_classifier.py` for every override.
- Document the override in the runbook change log.

---

## Runbook Change Log

| Date | Change | Author |
|---|---|---|
| 2026-07-03 | Initial runbook created. | Lanre Oluokun |

---

## References

- [`docs/DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md)
- [`docs/TESTING.md`](TESTING.md)
- [`context/THREAT_MODEL.md`](../context/THREAT_MODEL.md)
- [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md)
- [`adr/ADR-004-severity-response-matrix.md`](../adr/ADR-004-severity-response-matrix.md)
- [`adr/ADR-008-cost-strategy-under-20-usd.md`](../adr/ADR-008-cost-strategy-under-20-usd.md)
