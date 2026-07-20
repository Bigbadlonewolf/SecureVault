# SecureVault Testing Guide

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

This guide covers local unit testing, local Cloud Function emulation, cloud integration testing, and security scanning. All commands assume you are in the repository root unless otherwise noted.

For deployment steps, see [`docs/DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md). For operational response procedures, see [`docs/OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md).

---

## Local Development Setup

1. Create a Python virtual environment:

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r src/requirements.txt
   pip install pytest functions-framework
   ```

3. Set required environment variables for local runs:

   ```bash
   export PROJECT_ID=YOUR_GCP_PROJECT_ID
   export REGION=us-central1
   export ALERT_EMAIL=security-team@example.com
   export BREVO_SECRET_ID=brevo-api-key
   export BIGQUERY_DATASET=securevault_analytics
   export BIGQUERY_TABLE=findings_history
   export LOG_LEVEL=DEBUG
   ```

   For pure unit tests, these values can be placeholder strings because GCP calls are mocked.

   You can also run the convenience target:
   ```bash
   make test
   ```

---

## Local Unit Tests

Run the full unit test suite with `pytest`:

```bash
pytest tests/ -v
```

Or use the Makefile:

```bash
make test
```

### Test Coverage

| Test File | Focus |
|---|---|
| `tests/test_classifier.py` | Severity mapping, class overrides, default behavior |
| `tests/test_remediator.py` | Remediation handlers, unmapped CRITICAL skip, error handling |
| `tests/test_notifier.py` | Brevo payload format, graceful failure, Secret Manager mocking |
| `tests/test_main.py` | Pub/Sub CloudEvent parsing and entry-point orchestration |
| `tests/test_integration.py` | End-to-end pipeline from Pub/Sub message to storage |

### Expected Output

A successful run reports 29 passing tests with no failures or errors.

```text
======================== test session starts ========================
...
tests/test_classifier.py::test_classify_critical PASSED
tests/test_classifier.py::test_classify_high PASSED
tests/test_classifier.py::test_classify_medium PASSED
tests/test_classifier.py::test_classify_override_elevates_public_bucket_to_critical PASSED
tests/test_classifier.py::test_classify_unknown_severity_defaults_to_medium PASSED
...
======================== 29 passed in 1.23s ========================
```

### Running a Single Test File

```bash
pytest tests/test_classifier.py -v
```

### Running with Coverage

```bash
pip install pytest-cov
pytest tests/ --cov=src --cov-report=term-missing
```

---

## Local Function Emulation

Use the `functions-framework` to emulate the Cloud Function locally without deploying to GCP.

1. Start the emulator in CloudEvent mode (the same mode Gen 2 + Eventarc uses in production):

   ```bash
   cd src
   functions-framework --target=process_scc_finding --signature-type=cloudevent
   ```

   The emulator listens on `http://localhost:8080` by default and loads the handler from `src/main.py`.

2. In another terminal, publish a test event. Eventarc delivers Pub/Sub messages as structured CloudEvents, so POST a full CloudEvent envelope with the Pub/Sub message in `data.message.data` (base64-encoded):

   ```bash
   PAYLOAD=$(echo '{"finding":{"name":"projects/test/sources/123/findings/f1","resourceName":"//storage.googleapis.com/test-bucket","category":"PUBLIC_BUCKET_ACL","severity":"CRITICAL","findingClass":"MISCONFIGURATION","createTime":"2026-07-03T12:00:00Z"}}' | base64 -w0)

   cat > /tmp/test_event.json <<EOF
   {
     "specversion": "1.0",
     "id": "test-event-1",
     "source": "//pubsub.googleapis.com/projects/test/topics/scc-findings",
     "type": "google.cloud.pubsub.topic.v1.messagePublished",
     "time": "2026-07-03T12:00:00Z",
     "data": {
       "message": {
         "data": "$PAYLOAD",
         "messageId": "test-message-1",
         "publishTime": "2026-07-03T12:00:00Z"
       },
       "subscription": "projects/test/subscriptions/eventarc-scc-findings"
     }
   }
   EOF

   curl -X POST http://localhost:8080 \
     -H "Content-Type: application/cloudevents+json" \
     -d @/tmp/test_event.json
   ```

3. Observe the terminal running the emulator for structured log output.

### Troubleshooting Local Emulation

| Symptom | Fix |
|---|---|
| `ImportError` on `google.cloud` | Install `src/requirements.txt` in the active virtual environment. |
| `MissingTargetException` naming the entry point | Run `functions-framework` from the `src/` directory so it loads `src/main.py`, and confirm the target is `process_scc_finding`. |
| `config.yaml not found` | Run `functions-framework` from the `src/` directory. |
| `400` or parse error on POST | Send a structured CloudEvent (`--signature-type=cloudevent` with `Content-Type: application/cloudevents+json`), not a raw Pub/Sub JSON body. |
| Brevo call fails | This is expected if no valid secret is configured; the function should log and return `200`. |

---

## Integration Test in GCP

After deploying the pipeline, publish a real Pub/Sub message and verify all downstream outputs.

### Step 1: Publish a Test Message

Use the provided simulator to publish a sample finding:

```bash
export PROJECT_ID=YOUR_GCP_PROJECT_ID
python scripts/simulate_finding.py --project $PROJECT_ID --finding-class PUBLIC_BUCKET_ACL
```

Or publish manually with `gcloud`:

```bash
export PROJECT_ID=YOUR_GCP_PROJECT_ID

PAYLOAD=$(echo '{
  "finding": {
    "name": "projects/'$PROJECT_ID'/sources/123/findings/TEST-001",
    "resourceName": "//storage.googleapis.com/projects/_/buckets/test-bucket",
    "category": "PUBLIC_BUCKET_ACL",
    "severity": "CRITICAL",
    "findingClass": "MISCONFIGURATION",
    "createTime": "2026-07-03T12:00:00Z",
    "eventTime": "2026-07-03T12:00:00Z"
  }
}' | base64 -w0)

gcloud pubsub topics publish projects/$PROJECT_ID/topics/scc-findings --message="$PAYLOAD"
```

### Step 2: Verify Cloud Function Execution

```bash
gcloud functions logs read scc-processor --limit=20
```

Look for log lines indicating classification, remediation, notification, and storage writes.

### Step 3: Verify Firestore

```bash
gcloud firestore documents get \
  projects/$PROJECT_ID/databases/(default)/documents/remediation_log/projects/$PROJECT_ID/sources/123/findings/TEST-001
```

You should see fields such as `finding_id`, `resource`, `severity`, `action`, `status`, and `processedAt`.

### Step 4: Verify BigQuery

```bash
bq query --use_legacy_sql=false \
  "SELECT * FROM \`$PROJECT_ID.securevault_analytics.findings_history\` WHERE finding_id='projects/$PROJECT_ID/sources/123/findings/TEST-001'"
```

### Step 5: Verify Email (Optional)

If the finding was CRITICAL or HIGH, check the `alert_email` inbox for a Brevo alert.

---

## Security Scanning

All source code and infrastructure must pass the scanners from Stage 7 before any deployment.

### Required Scanners

| Scanner | Command | Scope |
|---|---|---|
| `bandit` | `bandit -r src/ scripts/ -f json -o bandit-report.json` | Python security anti-patterns |
| `pip-audit` | `pip-audit --format=json --desc -r src/requirements.txt` | Vulnerable Python dependencies |
| `Checkov` | `checkov --directory terraform/ -o json` | Terraform misconfigurations |
| `gcloud secrets scan` | `gcloud secrets scan --source=src/` | GCP secret-exposure detection |
| `truffleHog` | `truffleHog filesystem src/` | Deep secret detection |
| `tfsec` | `tfsec terraform/` | Terraform-specific security checks |

### Running the Full Scan Suite

```bash
# Python SAST
bandit -r src/ scripts/ -f json -o bandit-report.json

# Dependency audit
pip-audit --format=json --desc -r src/requirements.txt

# Terraform IaC scan
 checkov --directory terraform/ -o json

# GCP secret scan
gcloud secrets scan --source=src/

# Deep secret scan
truffleHog filesystem src/

# Terraform-specific scan
tfsec terraform/
```

### Interpreting Results

- **Zero findings** is the target for all scanners before merging to `main`.
- Any finding must be fixed or suppressed with architect approval.
- Test fixtures containing fake secrets must be marked with `# nosec` and a comment explaining the data is synthetic.

### Remediation Rules

| Finding | Fix |
|---|---|
| `bandit B104` (hardcoded password) | Move the value to Secret Manager. |
| `bandit B605` (shell=True) | Refactor to `subprocess.run` without shell invocation. |
| `pip-audit` CVE | Upgrade to a patched version and verify compatibility. |
| `Checkov` public bucket | If intentional, add a comment justification; otherwise enable public access prevention. |
| Secret-like string in source | Rotate the credential immediately if real; exclude synthetic test data with `# nosec`. |
| `tfsec` missing encryption | Add CMEK or accept default GCP encryption with documented justification. |

### Security Scan Report

Results are recorded in `SECURITY_SCAN_REPORT.md` (produced during Stage 7 security scanning), including scanner versions, pass/fail status, every finding found, and how each was resolved.

---

## CI/CD Testing

GitHub Actions run the same scans and tests automatically through the unified `.github/workflows/ci.yml` workflow:

- **Python Tests** — runs `pytest` on every push and pull request.
- **Security Scan** — runs `bandit`, `pip-audit`, `Checkov`, and `truffleHog` on every push and pull request.
- **Terraform Plan** — runs `terraform fmt`, `validate`, and `plan` on pull requests in the canonical repository.
- `.github/workflows/deploy.yml` — manually triggered deployment after CI passes on `main`.

The legacy `security-scan.yml` and `terraform-plan.yml` workflows remain available for manual dispatch but are superseded by `ci.yml`.

Open a pull request to validate your changes through CI before deploying.

---

## References

- [`docs/DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md)
- [`docs/OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md)
- [`SECURITY_SCAN_REPORT.md`](../SECURITY_SCAN_REPORT.md)
- [`SECURITY.md`](../SECURITY.md)
- [`context/THREAT_MODEL.md`](../context/THREAT_MODEL.md)
