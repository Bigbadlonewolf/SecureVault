# Scale Architecture

**What this answers:** how the v0.1.x pipeline changes shape when it stops watching one project and starts watching an organisation of 500.

**Status:** design analysis against the deployed topology. Nothing here has been load-tested — see [Known Limitations](../README.md#known-limitations--phase-2). Where a number is an estimate rather than a measurement, it says so.

---

## What does not change

The ingestion path is already organisation-shaped, and this is the part most reference architectures get wrong by over-building it.

Security Command Center is an **org-level service**. Findings for every project in the organisation land in the same SCC instance, and a single notification config exports all of them to a single Pub/Sub topic. There is no per-project SCC to fan in from, so there is nothing to shard.

One topic. One subscription. One function. At 500 projects that is still one topic, one subscription, one function.

The instinct to add a topic per folder is the wrong one: it multiplies subscriptions and IAM bindings to solve a throughput problem that Pub/Sub does not have at this volume.

---

## What does change

### 1. Volume, and whether the current instance ceiling holds

The function is configured `max_instance_count = 10`, `available_memory = "256M"`, `timeout_seconds = 60`.

| Scale | Findings/day (est.) | Peak findings/sec (est.) | Verdict |
| --- | --- | --- | --- |
| 1 project, current | ~200 | <1 | Comfortable |
| 500 projects, steady state | ~100,000 | ~1–2 | Comfortable |
| 500 projects, first org-wide scan | ~500,000 in a few hours | ~40–100 | **Exceeds the ceiling** |

The steady-state number is not the binding constraint. The **initial enablement burst** is: turning SCC on across an org emits a backlog of every pre-existing misconfiguration at once, and that is a different workload from the trickle that follows.

At 10 instances × roughly 20 findings/sec each, the burst drains rather than drops — Pub/Sub retains and redelivers. The visible symptom is lag, not loss, provided the subscription's retention exceeds the drain time. `message_retention_duration` on the topic is currently **86,400s (1 day)**, chosen for cost. A drain that outruns retention loses findings silently.

**The change:** raise `max_instance_count` before an org-wide enablement, and raise topic retention to 7 days for the duration of the backfill. Both are one-line changes; the point is to make them *before*, not after.

### 2. Project metadata lookup becomes the hot path

Risk decisions need context the finding does not carry: is this project production, does it hold regulated data, who owns it. Today `classifier.py` reads `severity_overrides` from a static `config.yaml` shipped with the function.

At 500 projects a static file is wrong for two reasons: it goes stale the moment a project is created, and it cannot express per-project data classification.

**The change:** read project labels via Cloud Asset Inventory, cached. Not per-finding — a per-finding `projects.get` at 100 findings/sec is 100 API calls/sec against a quota that will not carry it, and it puts the pipeline's availability behind Resource Manager's.

Cache shape: an in-memory dict, refreshed on cold start plus a TTL of an hour, keyed by project number. On cache miss, fail **open to the higher severity** — an unclassified project is treated as sensitive until proven otherwise, because the alternative silently downgrades findings for projects nobody has labelled yet, which are exactly the projects most likely to be misconfigured.

### 3. A dead-letter topic stops being optional

**There is currently no dead-letter configuration.** The subscription sets `retry_policy = "RETRY_POLICY_RETRY"` and nothing else, so a message that fails deterministically — a finding shape the parser does not handle, a remediation call that always 403s — is retried until retention expires and is then dropped with no record.

At one project that is an acceptable gap; you would notice. At 500 it is the failure mode that hides a systematic parsing bug behind a wall of successful traffic.

**The change:**

- A `securevault-findings-dlq` topic with a subscription nothing consumes automatically.
- `dead_letter_policy` on the main subscription with `max_delivery_attempts = 5`.
- The DLQ depth published as a Cloud Monitoring metric, alerting on any sustained non-zero value.

A DLQ nobody looks at is a queue that grows. The alert is the deliverable, not the topic.

### 4. Remediation blast radius scales with the fleet

`PUBLIC_BUCKET_ACL` auto-remediation removing `allUsers` from one bucket in one project is a contained action. The same handler firing across 500 projects during a backfill can strip public access from every intentionally-public bucket in the organisation — a static site, a public dataset, a CDN origin — in the same few minutes.

This is the risk that grows fastest with scale and it is not a throughput problem, so no amount of instance tuning addresses it.

**The change:** a rate limit on remediation actions, separate from the ingestion rate. A ceiling of N remediations per hour org-wide, with everything above it downgraded to alert-only and logged as throttled. Plus a label-based opt-out — `securevault-exempt: true` on a project or bucket — checked before any write action.

Ingestion should scale. Remediation should not.

### 5. Alerting must aggregate or it becomes noise

At 200 findings/day, per-finding email is legible. At 100,000/day it is a self-inflicted denial of service on the person receiving it, and the practical result is that alerting gets muted and the pipeline becomes decorative.

**The change:** CRITICAL stays per-finding and immediate. Everything below aggregates into a scheduled digest keyed by project and finding class, with counts rather than instances. This is a change to `notifier.py`'s contract, not just its volume — it needs a store of what has already been reported to avoid re-alerting on the same open finding daily. The BigQuery `findings_history` table already holds the data required.

---

## Failure modes and recovery

| Failure | Blast radius | Recovery |
| --- | --- | --- |
| Function code throws on every message | All findings undelivered | Pub/Sub retains for `message_retention_duration`. Fix, redeploy, backlog drains. **RTO bounded by retention, currently 1 day** |
| Function exhausts `max_instance_count` | Delivery lag, no loss | Self-clearing. Raise ceiling if sustained |
| Metadata cache backend unavailable | Risk scores degrade | Fail to higher severity; pipeline continues |
| Remediation API returns 403 | That finding never remediates | Caught by DLQ once configured. Today: silently retried to expiry |
| Pub/Sub topic deleted | Total loss of in-flight findings | No recovery. SCC does not replay. Rebuild the notification config and accept the gap |
| BigQuery insert fails | Finding processed, no audit record | Logged as an error and `False` returned (`bigquery_client.py:66-84`), but the message is still acked and never retried |

The last row is the one worth acting on before scale, not after. The failure is not silent — it logs — but nothing acts on the log, so the outcome is the same: the finding was handled operationally and has no row in the evidence table. At one project you would spot it in the logs. At 500 it is a slow leak in the compliance record, and an audit pipeline whose audit write can fail without retry is not evidence. The fix is to make the BigQuery write failure nack the message so Pub/Sub redelivers, which is the same DLQ machinery item 3 asks for.

---

## Cost at 500 projects

Estimates, not measurements. Built from the same per-service reasoning as [ADR-008](../adr/ADR-008-cost-strategy-under-20-usd.md).

| Service | 1 project | 500 projects (est.) | Driver |
| --- | --- | --- | --- |
| Pub/Sub | \$0 | \$4–8 | ~10 GiB/month past the free tier |
| Cloud Functions | \$0 | \$8–15 | ~100k invocations/day, 256 MB, short runtime |
| BigQuery storage | \$0 | \$2–5 | ~100k rows/day, partitioned, 90-day retention |
| BigQuery queries | \$0 | \$0–5 | Free tier covers dashboards; unbounded ad-hoc scans do not |
| Cloud KMS | ~\$0.06 | ~\$0.06 | Per key version, volume-independent |
| Firestore | \$0 | \$1–3 | Operational state only |
| Secret Manager | ~\$0.06 | ~\$0.06 | One secret |
| **Total** | **under \$5** | **\$15–35/month** | |

This crosses ADR-008's \$20 ceiling. That ceiling was set for a portfolio project, and an org-wide security pipeline at \$35/month is not the thing to economise on — but the number should be stated rather than discovered. The two levers if it matters: BigQuery partition expiry, and dropping LOW findings before they are stored rather than after.

---

## What is not addressed here

- **Multi-region.** Single-region remains a Phase 2 item. This document assumes the pipeline scales in one region.
- **Multi-org.** One SCC instance is assumed. Multiple organisations means multiple notification configs and a routing decision this design does not make.
- **Per-team routing.** Findings go to one destination. Routing by owning team needs an ownership source of truth the pipeline does not have.
- **Anything measured.** Every number above is derived from service quotas and configured limits, not from a load test. [EVOLUTION.md](../EVOLUTION.md) Phase 2 item 7 is the load test that would replace them.
