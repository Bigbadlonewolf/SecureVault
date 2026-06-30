# SecureVault Architecture Decision Record

## Context

Financial institutions operating on GCP need real-time detection of critical misconfigurations. SCC Security Health Analytics provides this detection, but the native notification channels (email, Slack) lack customization and filtering granularity.

## Decision

Build a lightweight, event-driven pipeline that:
1. Listens to SCC findings via Pub/Sub
2. Filters for specific high-severity finding types
3. Formats actionable alerts
4. Delivers via email

## Why Not Native SCC Notifications?

| Native | SecureVault |
|---|---|
| Limited filtering (by severity only) | Filter by specific finding categories |
| Generic email format | Custom HTML with remediation guidance |
| No cost control | Runs entirely on GCP free tier |
| No testability | Full unit test coverage |

## Why These Three Findings?

| Finding | Frequency in Financial Services | Impact |
|---|---|---|
| PUBLIC_BUCKET_ACL | High (developer convenience) | Data breach, regulatory fine |
| OPEN_FIREWALL | Medium (legacy migration) | Lateral movement, data exfil |
| OVER_PRIVILEGED_SERVICE_ACCOUNT | High (default behavior) | Privilege escalation |

## Cost Model

Target: $0/month via free tier.

- Cloud Functions: 2M invocations/month free (we expect ~1K)
- Pub/Sub: 10GB/month free (we expect ~100MB)
- SendGrid: 100 emails/day free (we expect ~10-50)

## Threat Model

| Threat | Mitigation |
|---|---|
| Alert fatigue | Filtered to 3 high-impact finding types |
| False positives | Unit-tested parsing logic |
| Secret exposure | API key in Secret Manager, not env var |
| Function compromise | Dedicated SA with minimal permissions |

## Future Enhancements

- BigQuery sink for trend analysis
- Auto-remediation for public buckets
- Slack/Teams webhook integration
- JIRA ticket creation

## Status

**Accepted** — 2025-06-30
