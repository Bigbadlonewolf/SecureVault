# ADR-010: Deactivate Brevo's Source-IP Allowlist Rather Than Reinstate the Egress Path

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-08-20
- **Status:** Accepted
- **Amends:** [ADR-009](ADR-009-remove-vpc-connector-and-nat.md) — the first
  guardrail condition in that ADR triggered

## Context

ADR-009 removed the VPC connector, Cloud Router, and Cloud NAT on
2026-07-21, on the finding that the egress infrastructure had no
consumer. It listed four conditions that would reverse the decision.
The first read: *"Brevo, or any replacement alerting provider, requires
source-IP allowlisting. Brevo authenticates by API key, not source IP,
so this does not currently apply."*

That assessment was wrong. On 2026-08-20 the first live alerting attempt
returned 401. Three days of debugging treated it as a credential fault —
three API keys were generated, the wrong console tab was used twice, and
a key was rotated. The key was valid throughout.

The cause was found in Brevo's Security → Authorized IPs page:
"Blocking unauthorized IP addresses" was **Activated for API keys**,
Authorized IP addresses **0**, Unauthorized **2**. Every call was
rejected at the network layer regardless of credential validity. The
same key returned 401 from a workstation, confirming it was not a
Cloud Run issue.

Reinstating NAT would have satisfied ADR-009's guardrail as written.

## Decision

Deactivate Brevo's IP blocking for API keys. Do not reinstate the VPC
connector, Cloud Router, or Cloud NAT.

ADR-009's cost analysis still holds: the egress infrastructure costs
~$14–47/month and its only consumer would be one allowlist entry for a
single outbound HTTPS call. In a demo-scope project that trade is not
worth making. The guardrail correctly identified the condition; the
proportionate response at this scope is different from the one the
guardrail prescribed.

## Consequences

**Negative.** The alerting API key is usable from any source IP. If it
leaks, there is no network-layer containment. Detection and rotation
are the only remaining controls — and the key has already been exposed
once during debugging and rotated (version 10).

**Compensating.** The key is held in Secret Manager under CMEK, read at
instance start rather than embedded, and readable only by the processor
service account. Rotation is one new secret version; no redeploy,
because the function resolves `latest`.

**Operational — the control re-arms itself.** On 2026-08-21, after the
key was rotated, Brevo re-enabled IP blocking automatically with
Authorized IPs back at 0. It had to be deactivated a second time. A
security control that silently reactivates on credential rotation will
eventually be left on during an incident, at the worst moment. This
makes the current state a standing operational risk, not a settled one.

## Guardrail — conditions that reverse this decision

Reinstate the connector, Cloud Router, and Cloud NAT with a reserved
static egress address, then re-enable Brevo's allowlist with that one
address authorized, if any of the following becomes true:

- This pipeline is used outside a demo project.
- The alerting key is exposed again.
- A compliance obligation requires an attestable egress IP — this was
  already the fourth guardrail in ADR-009 and is unchanged.

## Lesson recorded

ADR-009 asserted a provider's authentication model without testing it,
and the assertion was load-bearing for a $14–47/month infrastructure
removal. The correct discipline is to verify a provider's network
controls before treating them as absent, not after the first 401.
