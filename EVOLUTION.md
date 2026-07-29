# SecureVault Evolution

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

This document tracks where SecureVault has been, where it is going, and why each Phase 2 item is prioritized the way it is.

---

## Version History

### v0.1.4 — ADR-009 implemented, review closeout, dead-code removal (2026-07-28)

**Goal:** Make the code match three decisions that had already been made on paper: ADR-009's VPC removal, ADR-004's alert-only ruling on `OVER_PRIVILEGED_SA`, and four standing review documents whose items were mostly closed but never marked closed.

**ADR-009 had never been implemented.** Status `Accepted`, dated 2026-07-21, specifying the removal of nine things from `terraform/`. All nine were still in `main.tf` at `HEAD` a week later. README §Security and README's cost-model note both asserted the removal had happened; `FIXES.md` said the opposite; the code agreed with `FIXES.md`.

Removed in this version:

- `google_compute_network.securevault`, `google_compute_subnetwork.securevault`, `google_compute_firewall.deny_all_ingress`
- `google_vpc_access_connector.securevault`, `google_compute_router.securevault`, `google_compute_router_nat.securevault`
- `vpcaccess.googleapis.com` from the enabled services list
- `vpc_connector` and `vpc_connector_egress_settings` from the function's `service_config`

The connector was configured `min_instances = 2`, `max_instances = 2` — a hard floor rather than the scale-to-zero ADR-009 described attempting. That is roughly \$14–\$47/month of idle compute routing traffic into a VPC with no resources in it and out again through NAT, against ADR-008's \$5 target.

`ingress_settings = "ALLOW_INTERNAL_ONLY"` is retained; it never depended on the connector. `compute.googleapis.com` is retained; the `OPEN_FIREWALL` remediation action needs it. `FIXES.md` §3 and `CHECKOV_SKIP.md` now carry supersession notes, and `CKV2_GCP_18` no longer applies because there is no VPC to flag.

**Also changed:**

- Removed `remove_excess_service_account_roles` from `processors/remediator.py`, along with its `_get_handler` registration and the now-unused `_extract_service_account_email` / `_is_predefined_role` helpers and `resourcemanager_v3` import.
- Added `test_over_privileged_sa_is_absent_from_the_auto_remediation_map` and `test_no_service_account_role_handler_is_registered`. The pre-existing behavioural test passed for the wrong reason if someone re-added the class pointing at a no-op; these assert the map and the registry directly.
- Folded `SecureVault-remediation.md`, `SecureVault-CI-issue-tracker.md`, `SecureVault-doc-corrections.md`, and `fix_securevault_critical.md` into this file and deleted them.

**Why the handler went.** It stripped every binding matching `roles/` from the flagged service account — including the primitive roles its own docstring claimed to retain, since primitives also start with `roles/`. SCC's `OVER_PRIVILEGED_SERVICE_ACCOUNT` finding does not identify *which* grant is excessive, so the handler could only ever remove all of them: a wider blast radius than the finding it was answering, unattended, on a CRITICAL trigger.

It was not reachable. `_AUTO_REMEDIATION_CLASSES` omitted the class and so did `CRITICAL.auto_remediate` in `src/config.yaml`, and a test already asserted `SKIPPED_UNMAPPED`. Deleting it closes the one remaining path — a future refactor re-registering it by name — and stops the code contradicting the ADR.

**Verification:** `pytest tests/ -q` → 31 passed. `terraform validate` → configuration is valid.

#### Closed items folded in from the retired trackers

| Item | Source | Resolution |
| --- | --- | --- |
| Finding-routing bug: `main.py` read `findingClass` directly instead of `category` | remediation | Closed — `main.py:47` routes through `_extract_finding_class()` |
| Test fixtures used a `findingClass` shape SCC never emits | remediation | Closed — fixtures rebuilt on the real schema |
| `FIXES.md` claimed Cloud Router + NAT that did not exist | remediation | Closed twice over. They were added after the tracker was written, then removed again by ADR-009 in this version. `FIXES.md` §3 now carries a supersession note |
| `vpc_connector_egress_settings` unset, defaulting to `PRIVATE_RANGES_ONLY` | remediation | Moot — the connector it configured is gone (ADR-009) |
| Over-privileged-SA remediation stripped every role | remediation | Closed by ADR-004 in policy; closed in code at v0.1.4 |
| `BREVO_API_KEY` never mounted from Secret Manager | fix-critical | Closed — `terraform/main.tf:261` `secret_environment_variables` |
| Four missing `__init__.py` causing cold-start `ModuleNotFoundError` | fix-critical | Closed — all four present |
| `requirements.txt` completeness unknown | fix-critical | Closed — 8 packages, matches imports |
| Run #9: `terraform validate` failing in 1s, root cause never found | CI tracker | Closed — validates clean. The tracker was right to refuse to guess; `backend.tf` and `terraform.tfvars` were both correctly ruled out |
| `terraform-plan.yml` had an unguarded duplicate of the auth failure | CI tracker | Closed — file deleted; `ci.yml` supersedes it |
| `ci.yml` and `security-scan.yml` ran contradictory Checkov policies | CI tracker | Closed — `security-scan.yml` removed; single `soft_fail: false` |
| `deploy.yml`'s `verify` job always exited 0 | CI tracker | Closed — queries the Checks API and fails on any red check |

#### Still open

**`deploy.yml` applies without surfacing a plan.** `terraform apply -auto-approve` at `deploy.yml:79` runs with no plan output for a human to read first. This is materially better than when the tracker was written — `needs: verify` is now a real gate and `environment: production` adds GitHub's approval step — so the original "one click from init to apply against production" is no longer accurate. What remains is that nobody sees the diff before it lands. A `terraform plan -out` step with the plan posted to the run summary, applied from the saved plan file, closes it.

### v0.1.3 — TruffleHog CI Fix (2026-07-03)

**Goal:** Fix the `Security Scan` job failure on every push to `main` where TruffleHog reported `BASE and HEAD commits are the same`.

**What changed:**

- Added `fetch-depth: 0` to the checkout step in `.github/workflows/ci.yml` so the full Git history is available.
- Changed TruffleHog `base` and `head` inputs to use conditional expressions:
  - `pull_request`: scans the diff between `github.base_ref` and `github.head_ref`.
  - `push`: scans the full repository history from the first commit to `HEAD`.

**Verification:**

- Workflow syntax validated locally.
- TruffleHog now scans correctly on both `push` and `pull_request` events.

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
| --- | --- | --- |
| 2026-07-03 | Keep v0.1.0 single-region | Cost and complexity control; DR is the first Phase 2 item. |
| 2026-07-03 | Restrict auto-remediation to 2 finding classes | Avoid false-positive outages; unmapped CRITICAL findings alert only. `OVER_PRIVILEGED_SA` was considered and rejected (ADR-004) — SCC does not say which grant is excessive. |
| 2026-07-28 | Implement ADR-009 rather than reverse it | The ADR was accepted on 2026-07-21 and never applied to `terraform/`. Two documents already described the world it specified; making the code agree was cheaper than re-arguing a decision that had been made. |
| 2026-07-03 | Use Brevo free tier | Satisfies zero-cost alerting constraint; fallback channel is Phase 2. |
| 2026-07-03 | Dual-write to Firestore + BigQuery | Firestore for operational speed; BigQuery for analytics and compliance evidence. |

---

## How to Propose Changes

See [`CONTRIBUTION.md`](CONTRIBUTION.md) for the contribution process, coding standards, and security review requirements.
