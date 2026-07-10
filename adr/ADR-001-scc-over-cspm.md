# ADR-001: Security Command Center over third-party CSPM

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

SecureVault needs a source of security findings in GCP that is native, stable, and cheap at low volume. Financial institutions already using GCP can either use the native Security Command Center (SCC) or purchase a third-party Cloud Security Posture Management (CSPM) product such as Prisma Cloud or Wiz. The choice affects licensing cost, data residency, integration complexity, and operational overhead.

## Decision

Use Google Security Command Center (SCC) as the sole findings source. SCC provides native Pub/Sub notifications, a stable findings schema, and requires no additional per-workload licensing.

## Consequences

**Positive:**

- No per-resource CSPM licensing; fits the under-$20/month cost constraint.
- Data never leaves the GCP trust boundary, supporting data-residency requirements.
- Native Pub/Sub notification path eliminates custom ingestion code.
- Findings schema is documented and versioned by Google.

**Negative:**

- Less detailed visualization and correlation than dedicated CSPM dashboards.
- No cross-cloud coverage; GCP-only environments only.
- Tuned detection rules are limited to what SCC and built-in services provide.

## Alternatives considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Prisma Cloud or Wiz | Rich dashboards, cross-cloud visibility, advanced correlation | Per-workload licensing, data egress to vendor, operational onboarding complexity | Rejected because cost and data-residency constraints outweigh visualization benefits for v0.1.0. |
| Manual SCC export / spreadsheet review | No infrastructure | Delayed, error-prone, unscalable | Rejected because it defeats the real-time response goal. |
| SIEM-only ingestion (e.g., Splunk, Chronicle) | Centralized analytics | Additional license and ingestion pipeline | Rejected as the primary source; may be revisited for Phase 2 correlation. |

## References

- [Google Cloud Security Command Center documentation](https://cloud.google.com/security-command-center/docs)
- [Security Command Center pricing](https://cloud.google.com/security-command-center/pricing)
- SecureVault [`context/COMPLIANCE_MAPPING.md`](../context/COMPLIANCE_MAPPING.md)
