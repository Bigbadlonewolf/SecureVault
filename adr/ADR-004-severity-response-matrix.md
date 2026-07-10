# ADR-004: Severity classification and response matrix

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

Not every finding should be auto-remediated. The response matrix must balance speed (closing attack paths quickly) with safety (avoiding production outages from overly aggressive automation). The matrix is the core policy engine of SecureVault.

## Decision

Adopt a severity-driven response matrix:

| Severity | Action | Rationale |
|---|---|---|
| **CRITICAL + mapped finding class** | Auto-remediate + immediate alert | Known, high-blast-radius misconfigurations with safe remediation paths. |
| **CRITICAL + unmapped finding class** | Immediate alert only; no remediation | Avoid destructive action on findings we have not modeled. |
| **HIGH** | Immediate alert; no auto-remediation | Requires human judgment before change. |
| **MEDIUM** | Log and include in daily digest | Trend analysis and hygiene tracking. |
| **LOW** | Log only | Noise reduction; available in BigQuery if needed. |

Mapped auto-remediation classes in v0.1.0:

- `PUBLIC_BUCKET_ACL`: remove `allUsers` / `allAuthenticatedUsers` from bucket IAM.
- `OPEN_FIREWALL`: disable firewall rule with `0.0.0.0/0` on sensitive ports.

`OVER_PRIVILEGED_SA` is deliberately not auto-remediated. SCC's finding identifies that a service account is over-privileged, not which specific role is excessive. A handler with no way to target the bad grant can only strip every predefined role on the account, a wider blast radius than the finding itself, on a CRITICAL-severity trigger with no human in the loop. It is treated as CRITICAL + unmapped: alert only, no remediation.

## Consequences

**Positive:**

- Limits blast radius by only auto-remediating well-understood findings.
- Ensures unmapped critical issues still reach a human.
- Provides clear escalation path from trend logging to immediate response.

**Negative:**

- Requires maintenance as new finding classes are added.
- A misclassified MEDIUM finding may not be reviewed quickly.

## Alternatives considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Auto-remediate every CRITICAL finding | Fastest response | High risk of breaking production on unfamiliar findings | Rejected; safety outweighs speed for unmapped findings. |
| Alert on everything; no remediation | Very safe | Misses the value of rapid closure for known misconfigurations | Rejected; the project goal is automated response. |
| Manual triage for all findings | Human judgment | Does not scale; defeats automation purpose | Rejected. |

## References

- [SCC finding severity](https://cloud.google.com/security-command-center/docs/how-to-manage-findings#viewing_finding_details)
- SecureVault [`context/THREAT_MODEL.md`](../context/THREAT_MODEL.md)
