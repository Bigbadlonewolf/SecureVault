# ADR-006: Brevo free tier over PagerDuty / SNS / Slack

- **Decision Owner:** Lanre Oluokun
- **Date:** 2026-07-03
- **Status:** Accepted
- **Implementation:** AI-assisted under architect direction

## Context

SecureVault needs a notification channel for CRITICAL and HIGH findings. For a personal, portfolio-grade pipeline, the cost ceiling is a hard constraint, but alerts must still reach a human when something is wrong.

## Decision

Use **Brevo’s free tier** for email alerting. The free tier provides 300 emails per day and a well-documented SMTP/API interface. If Brevo is unavailable, the function degrades gracefully by logging a critical error to Cloud Logging and continuing processing.

## Consequences

**Positive:**

- Zero cost for expected alert volumes.
- Simple REST API with Python `requests`.
- 300 emails/day is far above current and 10× scale alert volumes.

**Negative:**

- Free tier has no SLA.
- No native paging or on-call escalation.
- Daily cap could be exceeded at very high finding volumes.

## Alternatives considered

| Alternative | Pros | Cons | Verdict |
|---|---|---|---|
| PagerDuty | Industry standard for on-call, escalation policies, SLA | Paid tier required for meaningful use | Rejected due to hard cost ceiling; planned as Phase 2 fallback. |
| Amazon SNS + Email | Reliable, native cloud integration | Not zero-cost for email delivery; adds cross-cloud dependency | Rejected; Brevo is free and simpler. |
| Slack webhook | Team-friendly, instant visibility | Requires Slack workspace; not a true alerting channel | Rejected as primary channel; may supplement in Phase 2. |
| SendGrid free tier | Similar to Brevo | Slightly lower free daily limit at the time of evaluation | Rejected; Brevo’s 300/day fits better. |

## References

- [Brevo API documentation](https://developers.brevo.com/)
- [Brevo pricing](https://www.brevo.com/pricing/)
