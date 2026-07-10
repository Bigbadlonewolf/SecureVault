# ADR-005: BigQuery + Firestore over a single database

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

SecureVault needs two distinct storage capabilities: fast, schema-flexible operational state for recent findings, and cost-effective SQL analytics for trend reporting and audit review. A single database would force one access pattern to suffer.

## Decision

Use Firestore for operational state and BigQuery for historical analytics.

- Firestore: `remediation_log` collection keyed by finding ID. Used for fast lookups and recent-activity views.
- BigQuery: `securevault_analytics.findings_history` date-partitioned table. Used for trend queries, compliance reporting, and long-term audit.

## Consequences

**Positive:**

- Each store is optimized for its workload.
- Firestore free tier covers low-volume operational logging.
- BigQuery partitioning keeps analytics queries cheap.
- Dual writes provide resilience if one backend is temporarily unavailable.

**Negative:**

- Two storage clients to maintain.
- Eventual consistency between Firestore and BigQuery must be accepted.

## Alternatives considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Firestore only | Simple, fast lookups | Expensive for analytics; limited SQL support | Rejected; analytics are a first-class requirement. |
| BigQuery only | Single store, powerful SQL | Too slow for operational lookups; streaming insert cost per query | Rejected; operational state needs sub-second lookup. |
| Cloud SQL (PostgreSQL) | Familiar SQL, strong consistency | Baseline cost and operational overhead even at low scale | Rejected; overkill for current volume. |

## References

- [Firestore documentation](https://cloud.google.com/firestore/docs)
- [BigQuery documentation](https://cloud.google.com/bigquery/docs)
- SecureVault [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md)
