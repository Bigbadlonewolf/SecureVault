# ADR-003: Cloud Functions Gen 2 over Cloud Run over GKE

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

The SecureVault processor is a single-purpose event handler: receive a Pub/Sub message, classify it, take one action, log the result. The compute layer must be operationally simple, automatically scalable, and cost-effective at low volume.

## Decision

Deploy the processor as a **Cloud Functions Gen 2** function running Python 3.11, with a Pub/Sub event trigger, 256 MB memory, and a dedicated service account.

## Consequences

**Positive:**

- Simplest operational model: no container build, no service revision management.
- Built-in Pub/Sub event trigger and automatic scaling to zero.
- Generous free tier (2M invocations/month) keeps cost near zero.
- Fastest path to a working pipeline.

**Negative:**

- Less runtime flexibility than Cloud Run (no custom concurrency, limited networking).
- Not suitable if the pipeline later grows into a multi-service application.
- Cold-start latency may be noticeable for very infrequent findings.

## Alternatives Considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Cloud Run | More flexible runtime, custom concurrency, longer timeouts | Requires container image and revision management; slightly higher ops overhead | Rejected; flexibility is unnecessary for a single event handler. |
| GKE Autopilot | Full orchestration, multi-service ready | Significant operational complexity and baseline cost | Rejected as overkill for one function. |
| Cloud Functions Gen 1 | Slightly simpler IAM model | Smaller free tier, fewer features, Gen 2 is the recommended path | Rejected; Gen 2 is the strategic platform. |

## References

- [Cloud Functions Gen 2 overview](https://cloud.google.com/functions/docs/2nd-gen/overview)
- [Cloud Functions pricing](https://cloud.google.com/functions/pricing)
