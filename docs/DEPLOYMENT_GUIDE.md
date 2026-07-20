# SecureVault Deployment Guide

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

This guide walks through a fresh deployment of SecureVault into a GCP project. It assumes you have owner or equivalent IAM permissions on the target project.

For day-to-day operational procedures after deployment, see [`docs/OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md). For testing procedures, see [`docs/TESTING.md`](TESTING.md).

---

## Prerequisites

Before starting, confirm the following:

1. **GCP project** with billing enabled.
2. **Brevo account** and a valid API key (the key will be stored in Secret Manager, never in source code).
3. **Alert email address** to receive Brevo notifications and Cloud Monitoring alerts.
4. **Local tooling** installed:
   - [gcloud CLI](https://cloud.google.com/sdk/docs/install) authenticated to the target project
   - [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
   - Python 3.11 (for local testing)
5. **GCP APIs enabled.** Terraform will enable the required APIs, but you can pre-enable them to avoid delays:
   - `securitycenter.googleapis.com`
   - `pubsub.googleapis.com`
   - `cloudfunctions.googleapis.com`
   - `secretmanager.googleapis.com`
   - `firestore.googleapis.com`
   - `bigquery.googleapis.com`
   - `monitoring.googleapis.com`
   - `logging.googleapis.com`
   - `storage.googleapis.com`
   - `cloudasset.googleapis.com`
   - `iam.googleapis.com`

> **Security note:** Never commit the Brevo API key, service account keys, or `terraform.tfvars` to source control. The repository `.gitignore` already excludes these files.

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/Bigbadlonewolf/SecureVault.git
cd SecureVault
```

Review the architecture and context before deploying:

- [`README.md`](../README.md)
- [`context/THREAT_MODEL.md`](../context/THREAT_MODEL.md)
- [`context/COMPLIANCE_MAPPING.md`](../context/COMPLIANCE_MAPPING.md)
- [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md)

---

## Step 2: Configure `terraform.tfvars`

1. Copy the example variables file:

   ```bash
   cd terraform
   cp terraform.tfvars.example terraform.tfvars
   ```

2. Edit `terraform.tfvars` with your values:

   ```hcl
   project_id = "YOUR_GCP_PROJECT_ID"
   region     = "us-central1"

   # Use a multi-region value like nam5, or a regional value matching `region`.
   firestore_location = "nam5"

   # BigQuery dataset location.
   bigquery_location = "US"

   # Email address for Brevo alerts and Cloud Monitoring notifications.
   alert_email = "security-team@example.com"

   # Replace {project_number} with your GCP project number.
   scc_notification_service_account = "service-{project_number}@gcp-sa-scc-notification.iam.gserviceaccount.com"
   ```

3. Find your project number:

   ```bash
   gcloud projects describe YOUR_GCP_PROJECT_ID --format="value(projectNumber)"
   ```

4. Update `scc_notification_service_account` with that number.

---

## Step 3: Store the Brevo API Key in Secret Manager

Terraform creates an empty Secret Manager secret called `brevo-api-key`. The actual key value must be added **after** `terraform apply` so it never enters Terraform state or the repository.

1. Run Terraform first (see Step 4) so the secret and IAM bindings exist.

2. Obtain your Brevo API key from the [Brevo dashboard](https://app.brevo.com/).

3. Add the key as the first active Secret Manager version:

   ```bash
   echo -n "YOUR_BREVO_API_KEY" | gcloud secrets versions add brevo-api-key --data-file=-
   ```

4. Verify the function service account can access the secret:

   ```bash
   gcloud secrets get-iam-policy brevo-api-key
   ```

   You should see `roles/secretmanager.secretAccessor` granted to `scc-processor@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com`.

> **Why no placeholder version?** A disabled placeholder version causes the Cloud Function to fail at runtime when it reads `latest`. Terraform therefore creates only the secret container; the operator is responsible for populating the first real version.

---

## Step 4: Run Terraform

Initialize, plan, and apply the infrastructure.

```bash
terraform init
terraform plan
terraform apply
```

### What Terraform creates

| Resource | Purpose |
|---|---|
| `google_pubsub_topic.scc_findings` | Receives SCC finding notifications |
| `google_cloudfunctions2_function.scc_processor` | Processes findings (Python 3.11, Gen 2) |
| `google_service_account.scc_processor` | Dedicated, least-privilege runtime identity |
| `google_project_iam_custom_role.remediation` | Minimal permissions for auto-remediation |
| `google_secret_manager_secret.brevo_api_key` | Stores the Brevo API key |
| `google_firestore_database.default` | Operational state for recent findings |
| `google_bigquery_dataset.analytics` + `findings_history` | Historical analytics and audit |
| `google_monitoring_dashboard.securevault` | Operational dashboard |
| `google_monitoring_alert_policy.function_error_rate` | Alerts when function error rate > 5% |

Review the Terraform outputs for useful resource names:

```bash
terraform output
```

---

## Step 5: Deploy the Cloud Function

In this deployment model, the Cloud Function is built and deployed by Terraform during `terraform apply` from the source archive in `src/`. After applying, verify the function is deployed:

```bash
gcloud functions list --project=YOUR_GCP_PROJECT_ID
```

You should see `scc-processor` in the `us-central1` region.

If you make code changes after the initial deployment, redeploy by running `terraform apply` again. Terraform will detect the changed source archive and update the function.

> **Cost note:** The function is configured with 256 MB memory and `min_instance_count = 0` to remain within the generous Cloud Functions free tier.

---

## Step 6: Verify with a Test SCC Finding

You do not need to wait for a real SCC finding to verify the pipeline. Publish a simulated finding to the `scc-findings` topic.

1. Create a test message file:

   ```bash
   cat > /tmp/test_finding.json <<'EOF'
   {
     "finding": {
       "name": "projects/YOUR_GCP_PROJECT_ID/sources/123/findings/456",
       "parent": "projects/YOUR_GCP_PROJECT_ID",
       "resourceName": "//storage.googleapis.com/projects/_/buckets/test-bucket",
       "state": "ACTIVE",
       "category": "PUBLIC_BUCKET_ACL",
       "severity": "CRITICAL",
       "findingClass": "MISCONFIGURATION",
       "createTime": "2026-07-03T12:00:00Z",
       "eventTime": "2026-07-03T12:00:00Z",
       "sourceProperties": {}
     }
   }
   EOF
   ```

2. Publish the message:

   ```bash
   gcloud pubsub topics publish projects/YOUR_GCP_PROJECT_ID/topics/scc-findings \
     --message="$(cat /tmp/test_finding.json | base64 -w0)"
   ```

3. Watch the Cloud Function logs:

   ```bash
   gcloud functions logs read scc-processor --limit=50
   ```

   Alternatively, use Cloud Logging:

   ```bash
   gcloud logging read "resource.type=cloud_function resource.labels.function_name=scc-processor" --limit=20
   ```

4. Verify downstream results:

   - **Firestore:** Check the `remediation_log` collection for a document with ID matching the finding name.
   - **BigQuery:** Query `securevault_analytics.findings_history` for the new row.
   - **Email:** If the test finding was CRITICAL or HIGH, check the alert inbox.
   - **Monitoring dashboard:** Open the SecureVault Dashboard to see the finding appear.

5. To test a HIGH finding, change `"severity": "CRITICAL"` to `"severity": "HIGH"` and publish again. This should trigger an alert but not auto-remediation.

---

## Troubleshooting

### `terraform apply` fails with API not enabled

**Symptom:** Error message references an API that is not enabled.

**Fix:**

```bash
gcloud services enable API_NAME.googleapis.com --project=YOUR_GCP_PROJECT_ID
```

Wait 60 seconds, then re-run `terraform apply`.

### Cloud Function fails to deploy

**Symptom:** `terraform apply` fails during the Cloud Function build or deployment.

**Check:**

- The `src/` directory contains `main.py`, `requirements.txt`, and `config.yaml`.
- `main.py` exposes the entry point `process_scc_finding` (re-exported from the `scc_processor` package).
- The `functions-framework` dependency is present in `requirements.txt`.
- The Cloud Build API (`cloudbuild.googleapis.com`) is enabled.

### Function executes but no email is received

**Symptom:** Logs show processing, but no Brevo alert arrives.

**Check:**

1. The Brevo API key is stored correctly and at least one version is enabled:

   ```bash
   gcloud secrets versions list brevo-api-key
   ```

2. The `alert_email` value in `terraform.tfvars` is valid and not blocked by Brevo.
3. Brevo account has not exceeded the 300 emails/day free tier limit.
4. Cloud Logging shows a Brevo-related error with `status_code` details.

For a full playbook, see [`docs/OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md).

### Real SCC findings are not arriving

**Symptom:** The pipeline processes test messages but not real SCC findings.

**Check:**

1. SCC notifications are configured to publish to `projects/YOUR_GCP_PROJECT_ID/topics/scc-findings`.
2. The SCC notification service account is correctly set in `terraform.tfvars`.
3. The Pub/Sub topic IAM policy allows only the SCC service account to publish.

### Permission denied during auto-remediation

**Symptom:** Logs show `403` errors when the function attempts remediation.

**Fix:**

Verify the custom role is attached to the function service account:

```bash
gcloud projects get-iam-policy YOUR_GCP_PROJECT_ID \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:scc-processor@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com"
```

The output should include the custom role `securevault.remediator` (displayed as its full resource path).

### Cost exceeds expectations

**Symptom:** Monthly bill is climbing.

**Check:**

- Review the Cloud Billing dashboard to identify the service.
- Check Cloud Functions invocation count and memory usage.
- Confirm BigQuery queries are using the `timestamp` partition filter.
- Reduce `max_instance_count` or add Pub/Sub filtering if needed.

See [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md) for scaling guidance.

---

## Next Steps After Deployment

1. Set up a GCP billing alert at $15/month to catch unexpected growth before the $20 ceiling.
2. Configure Security Command Center notification settings to send findings to the `scc-findings` topic.
3. Run the full test suite locally as described in [`docs/TESTING.md`](TESTING.md).
4. Review the operational runbook for incident response procedures.

---

## References

- [`README.md`](../README.md)
- [`docs/OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md)
- [`docs/TESTING.md`](TESTING.md)
- [`adr/ADR-008-cost-strategy-under-20-usd.md`](../adr/ADR-008-cost-strategy-under-20-usd.md)
