# SecureVault

Event-driven GCP security findings pipeline. Detects misconfigurations in real time using Security Command Center (SCC) Security Health Analytics, routes alerts through Pub/Sub, and delivers actionable email notifications via Cloud Functions.

**Target cost: $0–5/month** via GCP free tier.

---

## Architecture

```
SCC Security Health Analytics
         │
         ▼
   Security Finding
   (PUBLIC_BUCKET_ACL, OPEN_FIREWALL,
    OVER_PRIVILEGED_SERVICE_ACCOUNT)
         │
         ▼
    Pub/Sub Topic
   (scc-findings-topic)
         │
         ▼
   Cloud Function v2
   (Python 3.12 runtime)
         │
         ▼
    Brevo SMTP
         │
         ▼
   Security Team Email
```

## Findings Covered

| Finding Type | Severity | Description |
|---|---|---|
| `PUBLIC_BUCKET_ACL` | Critical | Cloud Storage bucket exposed to `allUsers` or `allAuthenticatedUsers` |
| `OPEN_FIREWALL` | High | Firewall rule allows ingress from `0.0.0.0/0` on sensitive ports |
| `OVER_PRIVILEGED_SERVICE_ACCOUNT` | High | Service account granted primitive roles (`roles/editor`, `roles/owner`) |

## Quick Start

### Prerequisites

- GCP project with billing enabled
- `roles/cloudfunctions.developer`, `roles/pubsub.editor`, `roles/securitycenter.adminEditor`
- Brevo account (free tier: 300 emails/day)

### Deploy

```bash
# 1. Set variables
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project_id, email, and Brevo API key

# 2. Initialize and apply
terraform init
terraform plan
terraform apply

# 3. Verify — upload a public file to a GCS bucket
# You should receive an email alert within 60 seconds
```

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export BREVO_API_KEY=your-key
export ALERT_EMAIL=security@example.com

# Run unit tests
pytest tests/ -v
```

## Repository Layout

```
SecureVault/
├── main.py                  # Cloud Function entry point
├── requirements.txt         # Python dependencies
├── terraform/
│   ├── main.tf             # Core infrastructure
│   ├── variables.tf        # Input variables
│   ├── outputs.tf          # Output values
│   └── terraform.tfvars.example
├── .github/workflows/
│   └── ci.yml              # Terraform validate + Python lint
├── tests/
│   ├── test_handler.py     # Unit tests for Cloud Function
│   └── fixtures/
│       ├── public_bucket.json
│       ├── open_firewall.json
│       └── over_privileged_sa.json
└── docs/
    └── architecture.md     # Detailed architecture decisions
```

## CI Pipeline

| Stage | Tool | Purpose |
|---|---|---|
| Terraform Validate | `terraform validate` | Syntax and reference checking |
| Terraform Format | `terraform fmt -check` | Consistent formatting |
| Python Lint | `ruff` | Code quality |
| Unit Tests | `pytest` | Handler logic validation |

## Security Considerations

- Cloud Function runs with dedicated service account (least privilege)
- Brevo API key stored in Secret Manager, not in code or env vars
- No long-lived credentials in the repository
- Pub/Sub topic has IAM binding restricting publishers to SCC service account only

## Cost Breakdown (Free Tier)

| Component | Free Tier | Estimated Usage |
|---|---|---|
| Cloud Functions (v2) | 2M invocations/month | ~1K findings/month |
| Pub/Sub | 10GB/month | ~100MB/month |
| Brevo SMTP | 300 emails/day | ~50 emails/day |
| **Total** | | **$0/month** |

## Roadmap

- [ ] BigQuery sink for findings analytics
- [ ] Slack webhook integration
- [ ] Auto-remediation for public buckets (disable public access)
- [ ] JIRA ticket creation for tracking

## License

MIT
