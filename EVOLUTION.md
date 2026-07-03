# SecureVault Evolution

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

This document tracks where SecureVault has been, where it is going, and why each Phase 2 item is prioritized the way it is.

---

## Version History

### v0.1.2 — Production Hardening (2026-07-03)

**Goal:** Apply the production-grade security controls requested in `fix-prompt.pdf` and drive Checkov failures to zero.

**What changed:**

- Added a VPC, subnet, Cloud NAT, and VPC connector; restricted the Cloud Function ingress to `ALLOW_INTERNAL_ONLY`.
- Added a Cloud KMS key ring and crypto key with 90-day rotation; applied CMEK to Cloud Storage, Pub/Sub, BigQuery dataset, and BigQuery table.
- Enabled versioning, uniform bucket-level access, public-access prevention, and access logging on the source bucket.
- Added deletion protection to the KMS key and BigQuery table.
- Moved the Brevo API key from plain environment variables to `secret_environment_variables`.
- Added `local.common_labels` to every Terraform resource for ownership/IAM tracking.
- Added a Cloud Monitoring alert for high-severity SCC findings.
- Fixed TruffleHog checkout-depth issues and added Checkov SARIF upload in CI.
- Documented the single remaining intentional Checkov skip in `CHECKOV_SKIP.md`.

**Validation:**

- `pytest -q` — 23 passed
- `terraform validate` — success
- `checkov -d terraform/ --framework terraform --quiet` — 62 passed, 0 failed, 1 documented skip
- `bandit`, `pip-audit`, `truffleHog` — clean

### v0.1.0 — Initial Release (2026-07-03)

**Goal:** Build a credible, end-to-end detection and response pipeline that can survive a 20-minute technical deep dive by a hiring manager at a financial institution.

**What shipped:**

- Event-driven ingestion of Security Command Center findings via Cloud Pub/Sub.
- Cloud Functions Gen 2 processor (`src/scc_processor/main.py`) written in Python 3.11.
- Severity classification and response matrix:
  - CRITICAL + mapped → auto-remediate + alert
  - CRITICAL + unmapped → alert only
  - HIGH → alert
  - MEDIUM / LOW → log
- Three auto-remediation handlers:
  - `PUBLIC_BUCKET_ACL` — remove `allUsers` / `allAuthenticatedUsers`
  - `OPEN_FIREWALL` — disable overly permissive firewall rules
  - `OVER_PRIVILEGED_SA` — remove excess predefined roles
- Dual audit trail: Firestore (`remediation_log`) for operational state, BigQuery (`findings_history`) for analytics.
- Brevo email alerting with Secret Manager-backed API key.
- Terraform IaC with least-privilege IAM, custom remediation role, and publisher-restricted Pub/Sub topic.
- Cloud Monitoring dashboard and error-rate alert.
- CI pipeline with pytest, bandit, pip-audit, Checkov, and truffleHog.
- Comprehensive documentation: README, ADRs, threat model, compliance mapping, cost analysis, deployment guide, operations runbook, testing guide, and interview walkthrough.

**Known constraints:**

- Single-region deployment.
- Three auto-remediation classes only.
- Brevo free tier has no SLA.
- Tested with simulated findings, not production-scale SCC volume.

---

## Phase 2 Roadmap

Phase 2 focuses on **resilience**, **enterprise integration**, and **broader coverage** — in that order. Each item includes the problem it solves and the acceptance criteria that would define “done.”

### 1. Multi-Region Disaster Recovery

**Problem:** A regional outage would stop finding processing and leave the security team blind.

**Plan:**

- Deploy a standby `scc-processor` function in a second region (e.g., `us-east1`).
- Configure a second Pub/Sub subscription with a dead-letter topic in the primary region.
- Add a Cloud Monitoring-based health check that can trigger a notification if the primary region stops acking messages.
- Document a manual failover runbook; automation is Phase 3.

**Acceptance criteria:**

- Terraform can deploy both regions from a single variable toggle.
- Failover runbook tested in a sandbox project.
- RTO/RPO targets documented (target RTO < 30 minutes, RPO < 5 minutes).

### 2. Alerting Fallback Channel

**Problem:** Brevo free tier has no SLA. If Brevo is down or rate-limited, high-severity findings may go unacknowledged.

**Plan:**

- Add a secondary notification backend (PagerDuty Events API v2 or SNS → email/SMS).
- Implement exponential backoff with circuit-breaker logic for Brevo.
- Send CRITICAL alerts through both channels; send HIGH alerts through Brevo with PagerDuty fallback on failure.

**Acceptance criteria:**

- Unit tests simulate Brevo failure and verify fallback delivery.
- New secrets (`pagerduty-integration-key`) added to Terraform and CI scans.
- Both channels are exercised in a non-production project.

### 3. SOAR / Ticketing Integration

**Problem:** Email alerts do not close the loop with analyst workflows. There is no ticket, no assignment, no escalation.

**Plan:**

- Add webhook handlers for ServiceNow and/or Jira.
- Create one ticket per CRITICAL and HIGH finding, with severity, resource link, and remediation status.
- Update ticket state when auto-remediation succeeds or fails.

**Acceptance criteria:**

- Terraform includes optional ServiceNow/Jira secret and URL variables.
- `notifier.py` refactored into a pluggable notification bus.
- End-to-end test creates a ticket in a sandbox instance.

### 4. Expand Auto-Remediation Coverage

**Problem:** Only three finding classes are auto-remediated; many common misconfigurations still require manual response.

**Candidate classes:**

- Public Cloud SQL instance
- Open Cloud SQL authorized networks
- Public BigQuery dataset
- Over-privileged custom IAM role
- Unencrypted Cloud Storage bucket (CMEK enforcement)

**Plan:**

- Add new handlers in `src/scc_processor/processors/remediator.py`.
- Update `config.yaml` `severity_overrides` and `response_matrix.CRITICAL.auto_remediate` lists.
- Each new handler must include unit tests and a documented rollback procedure before it is enabled by default.

**Acceptance criteria:**

- At least two new handlers shipped.
- All handlers have 100% unit-test path coverage.
- Rollback procedures added to `docs/OPERATIONS_RUNBOOK.md`.

### 5. Analyst Workflow Tiering (L1/L2/L3)

**Problem:** All findings flow through the same pipeline; there is no routing based on asset criticality or analyst skill level.

**Plan:**

- Introduce an asset criticality tag lookup (from resource labels or a static mapping in `config.yaml`).
- Route HIGH findings on critical assets directly to L2/L3 channels (PagerDuty, Slack, Jira).
- Route MEDIUM findings on non-critical assets to a daily digest.

**Acceptance criteria:**

- Configurable routing table in `config.yaml`.
- Unit tests cover L1/L2/L3 routing decisions.
- Documentation updated with runbook examples.

### 6. Multi-Signal Correlation

**Problem:** SCC findings alone lack network context. A public bucket may be benign, or it may be paired with an open firewall rule that creates real exposure.

**Plan:**

- Ingest Cloud Armor logs, VPC Flow Logs, and Cloud IDS findings into a second Pub/Sub topic.
- Build a correlation window (e.g., 5-minute tumbling window) using Cloud Run or Dataflow.
- Elevate correlated signals to CRITICAL even if individual severities are lower.

**Acceptance criteria:**

- Correlation engine deployed as a separate, optional service.
- At least one correlation rule implemented and tested.
- Cost model updated in `context/COST_ANALYSIS.md`.

### 7. Production Load Testing

**Problem:** The pipeline has been validated with unit tests and simulated findings, not at production SCC volume.

**Plan:**

- Export a representative SCC finding dataset (anonymized) from a sandbox project.
- Replay the dataset at 1×, 10×, and 100× real-time speed using `scripts/simulate_finding.py` or a load generator.
- Measure latency, error rate, cost, and Firestore/BigQuery throughput.

**Acceptance criteria:**

- Load-test report added to `docs/`.
- Bottlenecks identified and documented, with fixes prioritized.
- Cost observed during load test is within 25% of the model in `context/COST_ANALYSIS.md`.

### 8. Explicit Log Retention & Lifecycle Policies

**Problem:** Log retention is inherited from GCP defaults; compliance assessors will ask for explicit retention rules.

**Plan:**

- Add BigQuery table expiration or partition-level lifecycle rules in Terraform.
- Configure Firestore TTL on `remediation_log` documents (e.g., 2 years).
- Document retention periods per framework requirement.

**Acceptance criteria:**

- Terraform includes retention/expiration resources.
- Retention matrix documented in `context/COMPLIANCE_MAPPING.md`.

---

## Decision Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-07-03 | Keep v0.1.0 single-region | Cost and complexity control; DR is the first Phase 2 item. |
| 2026-07-03 | Restrict auto-remediation to 3 finding classes | Avoid false-positive outages; unmapped CRITICAL findings alert only. |
| 2026-07-03 | Use Brevo free tier | Satisfies zero-cost alerting constraint; fallback channel is Phase 2. |
| 2026-07-03 | Dual-write to Firestore + BigQuery | Firestore for operational speed; BigQuery for analytics and compliance evidence. |

---

## How to Propose Changes

See [`CONTRIBUTION.md`](CONTRIBUTION.md) for the contribution process, coding standards, and security review requirements.
