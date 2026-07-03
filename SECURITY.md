# Security Policy

> **Architect:** Lanre Oluokun | **Implementation:** AI-assisted | **License:** MIT

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a Vulnerability

Please report security vulnerabilities by emailing **Lanreoluokunigbadwolf@gmail.com** or by opening a private security advisory on GitHub.

## Security Controls

- **No secrets in source code**: All sensitive configuration is loaded from Google Secret Manager at runtime.
- **Least privilege IAM**: The Cloud Function runs under a dedicated service account with minimal required permissions.
- **Pub/Sub IAM restriction**: The `scc-findings` topic denies all publishers except Security Command Center.
- **Encrypted at rest**: Firestore, BigQuery, Pub/Sub, and Secret Manager use GCP-managed or CMEK encryption by default.
- **Audit logging**: All actions are written to Firestore, BigQuery, and Cloud Audit Logs.

## Scanning

Every push is scanned by the unified [`CI`](.github/workflows/ci.yml) workflow:

- `pytest` for unit-test coverage
- `bandit` for Python security issues
- `pip-audit` for vulnerable dependencies
- `Checkov` for Terraform misconfigurations
- `truffleHog` for deep secret detection

## Known Limitations

- Brevo free tier is limited to 300 emails per day.
- Auto-remediation is limited to CRITICAL findings and three finding classes.
- The pipeline assumes SCC notifications are enabled in the target project.
- Single-region deployment with no multi-region DR.
- No SOAR integration (ServiceNow, Jira, PagerDuty) in v0.1.0.
- No analyst workflow tiering (single pipeline, no L1/L2/L3).
- Tested with simulated findings, not production-scale SCC volume.

Each limitation is tracked as a Phase 2 enhancement in [`EVOLUTION.md`](EVOLUTION.md).
