# SecureVault Cost Analysis

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

SecureVault is engineered to run continuously for pennies per month at low scale while staying under a hard ceiling of **$20/month** as volume grows. The target operating cost is **under $5/month**; a billing alert fires at **$15/month**.

## Pricing Assumptions

- **Message size:** Average SCC finding message ≈ 2 KB.
- **Function profile:** 256 MB memory, ~500 ms average execution time, 0.2 vCPU allocation.
- **Storage per finding:** One Firestore document, one BigQuery streamed row.
- **Alert volume:** At current and 10× scale, critical + high alerts remain well under Brevo’s free daily limit (300 emails/day).
- **Region:** `us-central1` / `US` multi-region for BigQuery.

## Per-Service Cost Breakdown

| Service | Free Tier | ~100 findings/mo | ~1,000 findings/mo | ~10,000 findings/mo | Optimization Measure |
|---|---:|---:|---:|---:|---|
| **Cloud Functions Gen 2** | 2M invocations; 400k GB-s; 200k GHz-s | $0 | $0 | $0 | 256 MB memory; `min_instance_count = 0`; short-lived invocations |
| **Cloud Pub/Sub** | 10 GiB/mo | $0 | $0 | $0 | 1-day message retention; small messages |
| **Cloud Firestore** | 1M reads/writes; 1 GiB storage | $0 | $0 | ~$0.10 | One small document per finding; no hot indexes |
| **BigQuery** | 10 GiB storage; 1 TiB queries | $0 | $0 | <$0.05 | Date-partitioned `findings_history`; streaming inserts only |
| **Secret Manager** | 6 active versions; 10k ops/mo | $0 | $0 | $0 | Single active version; cached at function cold start |
| **Cloud Monitoring** | Dashboards + email alerts free | $0 | $0 | $0 | Dashboards; one alert policy; email channel |
| **Brevo** | 300 emails/day | $0 | $0 | $0 | Free tier sufficient at these alert volumes |
| **Cloud Storage** | 5 GB standard storage | <$0.01 | <$0.01 | <$0.01 | Source zip < 1 MB; lifecycle not needed |

### Cost Detail Notes

- **Cloud Functions Gen 2** remains within the generous free tier even at 10,000 invocations/month because 10k executions consume only ~1,250 GB-seconds and ~1,000 GHz-seconds.
- **Pub/Sub** traffic at 10,000 messages/month is roughly 20 MB — far below the 10 GiB free tier.
- **Firestore** charges only after 1 million reads or writes per month. At 10,000 findings we use ~10k writes, so cost is effectively zero; a small storage charge may appear only if the dataset exceeds 1 GiB.
- **BigQuery** streaming inserts bill at ~$0.05 per 200 MB. At 10,000 rows/month (~10 MB) the charge rounds to less than one cent. Queries against the partitioned table scan minimal bytes because the partition key is `timestamp`.
- **Brevo**’s free tier allows roughly 9,000 emails/month. If alert volume grows beyond that, the first paid tier or a Cloud Monitoring–backed fallback channel becomes necessary.

## Monthly Totals

| Scale | Estimated Cost | Buffer (25%) | **Total with Buffer** | Verdict |
|---|---:|---:|---:|---|
| Current (~100 findings/mo) | ~$0.01 | $0.01 | **~$0.02** | ✅ Well under $5 target |
| 10× (~1,000 findings/mo) | ~$0.20 | $0.05 | **~$0.25** | ✅ Well under $5 target |
| 100× (~10,000 findings/mo) | ~$2.00 | $0.50 | **~$2.50** | ✅ Under $5 target; headroom to $20 ceiling |

Even with a generous 25% buffer, SecureVault stays comfortably under the **$5/month target** through 10,000 findings/month. The **$20/month ceiling** provides room for unexpected growth, repeated retries, or temporary log-volume spikes.

## Cost Controls & Alerting

1. **Function memory:** Pinned to 256 MB. Raising this is the first change that would materially increase cost.
2. **Pub/Sub retention:** Reduced from the default 7 days to 1 day, minimizing storage cost.
3. **BigQuery partitioning:** The `findings_history` table is partitioned daily so trend queries scan only relevant days.
4. **Billing alert:** A GCP budget alert is configured to notify at **$15/month**, well before the $20 ceiling.
5. **Cloud Monitoring alert:** Function error-rate alerts help catch runaway invocations or retry storms early.

## Scaling Plan

| Volume Trigger | Expected Change |
|---|---|
| **> 10,000 findings/mo** | Move from per-finding Firestore writes to a small hourly batch; BigQuery streaming remains cost-effective. |
| **> 50,000 findings/mo** | Add Cloud Functions concurrency tuning; consider filtering MEDIUM findings at the Pub/Sub subscription to reduce invocation count. |
| **> 100,000 findings/mo** | Evaluate Cloud Run for more granular CPU/memory tuning; introduce SCC export batching for historical backfill. |
| **Alert volume > 300/day** | Add a paid alerting channel (PagerDuty or SNS) as a fallback; keep Brevo for cost-sensitive path. |

## References

- [Google Cloud Functions pricing](https://cloud.google.com/functions/pricing)
- [Google Cloud Pub/Sub pricing](https://cloud.google.com/pubsub/pricing)
- [Google Cloud Firestore pricing](https://cloud.google.com/firestore/pricing)
- [Google Cloud BigQuery pricing](https://cloud.google.com/bigquery/pricing)
- [Brevo pricing](https://www.brevo.com/pricing/)
- [`adr/ADR-008-cost-strategy-under-20-usd.md`](../adr/ADR-008-cost-strategy-under-20-usd.md)
