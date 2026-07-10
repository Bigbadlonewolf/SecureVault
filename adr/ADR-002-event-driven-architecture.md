# ADR-002: Event-driven ingestion over polling

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

Once SCC is selected, findings must be delivered to the SecureVault processor. The two primary patterns are event-driven (SCC → Pub/Sub → Cloud Function) and polling (a scheduled job calls the SCC API).

## Decision

Use an **event-driven pipeline** built on Cloud Pub/Sub. SCC is configured to publish findings to the `scc-findings` topic, and the Cloud Function is triggered by new messages.

## Consequences

**Positive:**

- Near-real-time response to new findings.
- No SCC API quota consumption for polling.
- No missed findings between poll intervals.
- Pub/Sub decouples ingestion from processing and provides durable buffering.

**Negative:**

- Adds Pub/Sub topic and IAM management.
- Requires understanding of Pub/Sub retry and dead-letter semantics.
- Slightly more complex to test locally than a simple cron job.

## Alternatives considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Cloud Scheduler + periodic SCC API polling | Simpler to reason about; no Pub/Sub infrastructure | Consumes SCC API quota; latency equals poll interval; missed findings possible if job fails | Rejected because latency and reliability are more important than minimal infrastructure. |
| Direct Eventarc trigger from SCC | Even tighter integration | Higher learning curve and less documentation stability at the time of design | Rejected; Pub/Sub route is better documented and easier to restrict. |
| Batch export to Cloud Storage | Cheap for historical replay | Not real-time; adds parsing complexity | Rejected as primary ingestion; kept as a future replay option. |

## References

- [SCC finding notifications via Pub/Sub](https://cloud.google.com/security-command-center/docs/how-to-send-notifications)
- [Cloud Pub/Sub documentation](https://cloud.google.com/pubsub/docs/overview)
