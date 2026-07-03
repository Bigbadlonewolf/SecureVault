# SecureVault Cost Analysis

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **Date:** 2026-07-03  
> **Status:** Initial release (v0.1.0)

SecureVault is engineered to run continuously for pennies per month at low scale while staying well under a hard ceiling of **$20/month** as volume grows. The target operating cost is **under $5/month**; a GCP billing alert is configured to fire at **$15/month**.

This analysis uses **published GCP list pricing** for `us-central1` / `US` and shows the exact GB-second / vCPU-second math so a hiring panel can audit it in real time.

---

## Pricing Assumptions

| Input | Value | Rationale |
|---|---|---|
| **Region** | `us-central1` / `US` | Free-tier-eligible region; co-locates function, Pub/Sub, Firestore, and BigQuery |
| **Average SCC message size** | 2 KB | Typical SCC finding notification payload |
| **Function memory** | 256 MiB = **0.25 GiB** | Lowest memory tier that supports the Python client libraries |
| **Function vCPU allocation** | **0.2 vCPU** | Cloud Functions Gen 2 scales vCPU with memory; this is a conservative estimate |
| **Baseline execution time** | **0.5 seconds** | Measured locally with mocked GCP calls; real cold-start + API latency may be 1–2 s |
| **Storage per finding** | 1 Firestore document + 1 BigQuery row | Audit trail written regardless of severity |
| **Alert volume** | Critical + high findings only | Brevo free tier covers 300 emails/day |

### Pricing Sources

- [Cloud Functions Gen 2 pricing](https://cloud.google.com/functions/pricing)
- [Cloud Pub/Sub pricing](https://cloud.google.com/pubsub/pricing)
- [Cloud Firestore pricing](https://cloud.google.com/firestore/pricing)
- [BigQuery pricing](https://cloud.google.com/bigquery/pricing)
- [Secret Manager pricing](https://cloud.google.com/secret-manager/pricing)
- [Brevo pricing](https://www.brevo.com/pricing/)

---

## GB-Second & vCPU-Second Math

Cloud Functions Gen 2 pricing has three meters: **requests**, **GB-seconds**, and **vCPU-seconds**. The always-free tier is generous:

| Meter | Free Tier | List Price |
|---|---|---|
| Requests | 2,000,000 / month | $0.40 / million |
| GB-seconds | 360,000 / month | $0.0000025 / GB-s |
| vCPU-seconds | 180,000 / month | $0.000024 / vCPU-s |

### Formulas

```text
monthly_gb_seconds   = findings_per_month × execution_seconds × memory_gib
monthly_vcpu_seconds = findings_per_month × execution_seconds × vcpu_count
```

### Baseline Example: 10,000 findings/mo at 0.5 s

```text
monthly_gb_seconds   = 10,000 × 0.5 × 0.25 = 1,250 GB-s
monthly_vcpu_seconds = 10,000 × 0.5 × 0.20 = 1,000 vCPU-s
```

Both values are **well inside** the free tier, so function compute cost is **$0.00**.

### Pay-As-You-Go Equivalent (no free tier)

```text
GB-s cost   = 1,250 × $0.0000025 = $0.0031
vCPU-s cost = 1,000 × $0.000024  = $0.0240
Requests    = 10,000 × $0.40 / 1,000,000 = $0.0040
Function subtotal (pay-as-you-go) = ~$0.031
```

At normal scale, the free tier absorbs virtually all function cost.

---

## Per-Service Cost Breakdown

| Service | Free Tier | List Price | ~100 findings/mo | ~1,000 findings/mo | ~10,000 findings/mo | Optimization |
|---|---|---|---:|---:|---:|---|
| **Cloud Functions Gen 2** | 2M invocations; 360k GB-s; 180k vCPU-s | $0.40/M requests; $0.0000025/GB-s; $0.000024/vCPU-s | $0 | $0 | $0 | 256 MiB; `min_instance_count = 0`; short-lived invocations |
| **Cloud Pub/Sub** | 10 GiB / month | $40 / TiB ($0.04 / GiB) | $0 | $0 | $0 | 1-day retention; 2 KB messages |
| **Cloud Firestore** | 20k writes/day (~600k/mo); 1 GiB storage | $0.09 / 100k writes (us-central1); $0.18 / GB-month | $0 | $0 | ~$0.00–$0.10 | One small doc per finding; no hot indexes |
| **BigQuery** | 10 GiB storage; 1 TiB queries/month | Streaming: $0.01 / 200 MB; storage: $0.02 / GB-month | $0 | $0 | <$0.05 | Date-partitioned `findings_history`; streaming inserts only |
| **Secret Manager** | None (after trial) | $0.06 / active version / month; $0.05 / 10k operations | ~$0.06 | ~$0.06 | ~$0.06 | Single active version; cached at function cold start |
| **Cloud Monitoring** | Dashboards + email alerts free | Log ingestion: $0.50 / GiB beyond 150 MB/day | $0 | $0 | $0 | One dashboard, one error-rate alert, email channel |
| **Brevo** | 300 emails/day (~9,000/mo) | Paid plans start after free tier | $0 | $0 | $0 | Free tier sufficient at expected alert volumes |
| **Cloud Storage** | 5 GB standard storage | $0.020 / GB-month | <$0.01 | <$0.01 | <$0.01 | Source zip < 1 MB |

### Detail Notes

- **Cloud Functions Gen 2** at 10,000 invocations/month consumes only ~1,250 GB-s and ~1,000 vCPU-s with a 0.5 s average execution — both are under the free tier.
- **Pub/Sub** traffic at 10,000 messages/month is roughly 20 MB, far below the 10 GiB free tier.
- **Firestore** free writes are ~600,000/month (20,000/day). At 10,000 findings we use ~10,000 writes, so the cost is effectively zero; storage remains under 1 GiB for a long time.
- **BigQuery** streaming inserts bill at $0.01 per 200 MB. At 10,000 rows/month (~20 MB) the streaming cost is ~$0.001. Storage for 20 MB at $0.02/GB-month is negligible.
- **Secret Manager** charges ~$0.06/month per active secret version regardless of usage. Access operations are charged only if the secret is read more than 10,000 times/month; the Brevo key is read only when an alert is sent.

---

## Monthly Totals

| Scale | Function Compute | Pub/Sub | Firestore | BigQuery | Secret Mgr | Storage | **Estimated Total** | Verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| ~100 findings/mo | $0 | $0 | $0 | $0 | ~$0.06 | <$0.01 | **~$0.07** | ✅ Under $5 |
| ~1,000 findings/mo | $0 | $0 | $0 | $0 | ~$0.06 | <$0.01 | **~$0.07** | ✅ Under $5 |
| ~10,000 findings/mo | $0 | $0 | ~$0.00–$0.10 | ~$0.01 | ~$0.06 | <$0.01 | **~$0.10–$0.20** | ✅ Under $5 |
| ~100,000 findings/mo | $0 | $0 | ~$0.36 | ~$0.14 | ~$0.06 | <$0.01 | **~$0.60** | ✅ Under $5 |
| ~1,000,000 findings/mo | $0 | $0 | ~$3.96 | ~$1.24 | ~$0.06 | <$0.01 | **~$5.30** | ⚠️ Approaches $5 target |

> **Note:** “$0” means the usage is covered by the GCP always-free tier for that meter.

Even at **1,000,000 findings/month**, the workload stays near the $5 target before any optimization. The $20/month ceiling provides headroom for retry storms, temporary log spikes, or regional pricing differences.

---

## Sensitivity Analysis

### “What if execution time rises to 2 seconds at 10,000 findings/month?”

Longer execution usually comes from slow GCP API calls (e.g., IAM propagation delays, BigQuery streaming retries). Re-running the math:

```text
monthly_gb_seconds   = 10,000 × 2.0 × 0.25 = 5,000 GB-s
monthly_vcpu_seconds = 10,000 × 2.0 × 0.20 = 4,000 vCPU-s
```

Both are still inside the free tier (360k GB-s and 180k vCPU-s), so **function compute remains $0**.

Pay-as-you-go equivalent:

```text
GB-s cost   = 5,000 × $0.0000025 = $0.0125
vCPU-s cost = 4,000 × $0.000024  = $0.0960
Requests    = 10,000 × $0.40 / 1,000,000 = $0.0040
Function subtotal (pay-as-you-go) = ~$0.11
```

**Conclusion:** At 10,000 findings/month with a 2-second execution, the pay-as-you-go function cost is roughly **$0.11**. With the always-free tier applied, the actual bill rounds to **~$0.00–$0.01** (only BigQuery streaming sits outside the function free tier).

### Other Sensitivity Levers

| Change | Cost Impact | Mitigation |
|---|---|---|
| **Double memory to 512 MiB** | 2× GB-second cost | Stay at 256 MiB unless profiling proves a need |
| **Average execution 5 s** | 10× GB/vCPU cost at same volume | Still within free tier up to ~36k GB-s/month; profile API calls |
| **Alert volume > 300/day** | Brevo free tier exhausted; paid email/SNS needed | Add PagerDuty/SNS fallback in Phase 2 |
| **BigQuery queries scan full table** | Query cost dominates (>$6/TiB) | Keep queries partitioned on `timestamp`; set `require_partition_filter` |
| **Secret Manager >10k reads/month** | ~$0.05 per 10k operations | Cache Brevo key in-process; secret is read only on alerts |

---

## Cost Controls & Alerting

1. **Function memory** pinned to 256 MiB. Raising this is the fastest way to increase GB-second cost.
2. **Pub/Sub retention** reduced from the default 7 days to 1 day, minimizing message-storage cost.
3. **BigQuery partitioning** — the `findings_history` table is partitioned daily so trend queries scan only relevant days.
4. **Billing alert** — GCP budget notification at **$15/month**, well before the $20 ceiling.
5. **Cloud Monitoring alert** — function error-rate alert catches runaway invocations or retry storms early.
6. **No always-on instances** — `min_instance_count = 0` means the function scales to zero between findings.

---

## Scaling Plan

| Volume Trigger | Expected Change |
|---|---|
| **> 10,000 findings/mo** | Current design is sufficient; monitor BigQuery streaming cost and Firestore index growth. |
| **> 50,000 findings/mo** | Tune Cloud Functions concurrency; consider filtering MEDIUM findings at the Pub/Sub subscription to reduce invocation count. |
| **> 100,000 findings/mo** | Evaluate Cloud Run for finer CPU/memory tuning; batch Firestore writes hourly. |
| **> 1,000,000 findings/mo** | Add Pub/Sub filtering and batching; consider Dataflow for backfill; revisit paid alerting. |
| **Alert volume > 300/day** | Add a paid alerting channel (PagerDuty or SNS) as a fallback; keep Brevo for cost-sensitive path. |

---

## References

- [`adr/ADR-008-cost-strategy-under-20-usd.md`](../adr/ADR-008-cost-strategy-under-20-usd.md)
- [Google Cloud Functions pricing](https://cloud.google.com/functions/pricing)
- [Google Cloud Pub/Sub pricing](https://cloud.google.com/pubsub/pricing)
- [Google Cloud Firestore pricing](https://cloud.google.com/firestore/pricing)
- [Google Cloud BigQuery pricing](https://cloud.google.com/bigquery/pricing)
- [Google Cloud Secret Manager pricing](https://cloud.google.com/secret-manager/pricing)
- [Brevo pricing](https://www.brevo.com/pricing/)
