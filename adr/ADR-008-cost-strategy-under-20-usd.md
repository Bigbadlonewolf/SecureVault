# ADR-008: Cost Strategy for Continuous Operation Under $20/Month

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

SecureVault is intended to be a continuously running, portfolio-grade security pipeline without the budget of an enterprise SOC. A hard cost ceiling of **$20/month** is set, with a target operating cost of **under $5/month**. Every architectural choice must respect this constraint.

## Decision

Optimize each component for the free tier and low-volume usage:

- **Cloud Function:** 256 MB memory, Gen 2, `min_instance_count = 0`.
- **Pub/Sub:** 1-day message retention on `scc-findings`.
- **Firestore:** One small document per finding; no hot indexes.
- **BigQuery:** Date-partitioned `findings_history` table; streaming inserts only.
- **Secret Manager:** Single active secret version.
- **Monitoring:** Native dashboard + one email alert policy.
- **Alerting:** Brevo free tier.

Set a billing alert at **$15/month** so there is time to react before the $20 ceiling is reached.

## Consequences

**Positive:**

- Current and 10× scale costs remain under $1/month.
- 100× scale is projected to stay under $5/month with buffer.
- Free tier utilization is tracked and documented.

**Negative:**

- Free tier limits must be monitored as volume grows.
- Brevo free tier has no SLA.
- Longer Pub/Sub retention and higher function memory would improve resilience but increase cost.

## Scaling Plan

| Scale | Cost Expectation | Triggered Change |
|---|---|---|
| ~100 findings/mo | ~$0.02 | None. |
| ~1,000 findings/mo | ~$0.25 | None. |
| ~10,000 findings/mo | ~$2.50 | Evaluate Firestore batching; confirm Brevo volume. |
| > 50,000 findings/mo | Re-evaluate | Add Pub/Sub filtering; consider Cloud Run for finer cost control. |
| > $15/mo | Billing alert | Architect review before any ceiling breach. |

## Alternatives Considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| 512 MB or 1 GB function memory | Faster cold starts, more headroom | Increases memory cost; unnecessary at this scale | Rejected. |
| 7-day Pub/Sub retention (default) | More replay buffer | Higher storage cost; 1 day is sufficient | Rejected. |
| Non-partitioned BigQuery table | Simpler schema | Queries scan full history, raising cost | Rejected. |
| Paid alerting from day one | SLA-backed notifications | Violates the under-$5 target | Rejected; kept as Phase 2 fallback. |

## References

- [Google Cloud pricing calculator](https://cloud.google.com/products/calculator)
- SecureVault [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md)
