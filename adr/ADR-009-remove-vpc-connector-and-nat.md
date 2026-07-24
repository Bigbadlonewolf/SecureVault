# ADR-009: Remove VPC Connector, Cloud NAT, and VPC from the Egress Path

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-21
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction
- **Supersedes:** The v0.1.2 hardening decision recorded in [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md), which added VPC and Cloud NAT. Does not amend [ADR-008](ADR-008-cost-strategy-under-20-usd.md), whose cost targets this decision restores.

## Context

The v0.1.2 hardening pass added a VPC, a Serverless VPC Access connector, a Cloud Router, and Cloud NAT, routing all Cloud Function egress through the VPC (`vpc_connector_egress_settings = "ALL_TRAFFIC"`). This was a deliberate choice in favour of production-grade security posture, and was documented as knowingly exceeding the under-$5 target.

A cost trace of the planned topology (from `terraform plan`, not a live deployment — see verification note below) found the justification does not hold:

1. **The VPC contains no resources.** No Cloud SQL, no Memorystore, no VMs. A VPC connector exists to reach private resources inside a VPC; there were none. Traffic entered an empty network and left immediately through NAT.
2. **`google_compute_subnetwork.securevault` (10.0.0.0/28) was orphaned.** The connector provisioned its own `10.0.1.0/28` range. Nothing consumed the subnet, which nonetheless carried VPC flow logs at 0.5 sampling.
3. **The only external egress target in the codebase is `https://api.brevo.com`.** Everything else is Google APIs, reachable without VPC egress.
4. **The connector could not scale to zero.** `min_instances = 0` was set, but the plan showed `min_throughput = 200` defaulted in. At 100 Mbps per e2-micro connector instance, this pins a floor of 2 instances permanently. The intended scale-to-zero never applied.

The connector and Cloud NAT were therefore load-bearing for each other, not for the workload.

## Decision

Remove from `terraform/`:

- `google_vpc_access_connector.securevault`
- `google_compute_router.securevault`
- `google_compute_router_nat.securevault`
- `google_compute_network.securevault`
- `google_compute_subnetwork.securevault`
- `google_compute_firewall.deny_all_ingress`
- `vpcaccess.googleapis.com` from the enabled services list
- The `vpc_connector` output
- `vpc_connector` and `vpc_connector_egress_settings` from the function's `service_config`

The Cloud Function reaches `api.brevo.com` over Google-managed egress.

**Rejected: Direct VPC egress.** It preserves the controlled-egress narrative without connector instances, but still requires Cloud NAT for a stable egress IP and retains a VPC with nothing in it. It fails the same test this ADR applies — infrastructure whose only consumer is itself.

**Retained: `compute.googleapis.com`.** Still required by the OPEN_FIREWALL remediation action, which disables overly permissive firewall rules.

**Retained: `ingress_settings = "ALLOW_INTERNAL_ONLY"`.** Independent of the connector; correctly restricts function invocation.

## Guardrail — conditions that reverse this decision

Reinstate the connector, Cloud Router, and Cloud NAT if any of the following becomes true:

- **Brevo, or any replacement alerting provider, requires source-IP allowlisting.** Brevo authenticates by API key, not source IP, so this does not currently apply. Confirmed as non-blocking at the time of this decision. Re-check on any provider change.
- A private resource is introduced that the function must reach — Cloud SQL, Memorystore, an internal load balancer, or a private GKE endpoint.
- A VPC Service Controls perimeter is established around the project. No `google_access_context_manager_*` resources exist today.
- A compliance obligation requires a static, attestable egress IP.

Any of these makes the VPC egress path genuinely load-bearing, and the ~$14–47/month becomes justified spend rather than idle cost.

## Consequences

**Positive:**

- Removes 7 resources; plan drops from 51 to 44.
- Eliminates the only always-on compute in the project. Restores ADR-008's under-$5 operating target, which the v0.1.2 topology breached.
- Removes VPC flow logging on a subnet carrying no traffic.

**Negative:**

- Loses a stable egress IP. Reversible via the guardrail above.
- Loses "no direct internet egress from compute" as an interview talking point. The honest replacement is stronger: *the egress control was removed because it protected nothing, and here is the trace that showed it.*

**Requires verification at apply time:**

- `ALLOW_INTERNAL_ONLY` ingress with no user VPC present. Eventarc and Pub/Sub traffic originate inside the project and should still satisfy internal ingress, but this has not been confirmed against a live deployment. If the trigger fails to deliver after apply, this is the first thing to check.

## Alternatives Considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| Keep as-is | No work; preserves security narrative | Pinned at 2 e2-micro instances to reach an empty VPC; breaches ADR-008 | Rejected. |
| Fix `min_instances` to 2 | Makes the config valid | Legitimises a component that serves nothing | Rejected. |
| Direct VPC egress | Keeps controlled-egress posture, no connector instances | Still needs NAT; still an empty VPC | Rejected — see Decision. |
| Full removal | Restores cost target; deletes infrastructure with no consumers | Loses static egress IP | **Accepted.** |

## References

- [`context/COST_ANALYSIS.md`](../context/COST_ANALYSIS.md) — cost model, corrected in the same change as this ADR
- [ADR-006](ADR-006-brevo-free-tier-alerting.md) — Brevo as the alerting transport
- [ADR-008](ADR-008-cost-strategy-under-20-usd.md) — the cost ceiling this decision restores
- [Serverless VPC Access documentation](https://cloud.google.com/vpc/docs/serverless-vpc-access)
