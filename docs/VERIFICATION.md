# Verification

What has been checked against a live deployment, and what has not. A claim
in this repo is either traceable to an entry here or it is untested.

## Evidence

### Pipeline, end to end

Last recorded full trace: `make simulate-finding` against
`securevault-demo`, 2026-08-20.

| Step | Result |
| --- | --- |
| Pub/Sub receive | OK |
| Processing finding | OK |
| Remediation handler | Failed — 404 on `allow-all-ssh`. Expected; the rule does not exist in the project |
| Brevo alert | Failed — see note below |
| Firestore action log | OK |
| BigQuery stream | OK |
| Processing complete | OK |

**The Brevo row is stale and is kept for the trail.** At the time it was
read as a credential-type fault. The cause was the source-IP allowlist
([ADR-010](../adr/ADR-010-alerting-source-ip-allowlist.md)), and a
second fault — a sender domain that did not exist — was fixed
afterwards in `3c96a47` on 2026-08-21. **No end-to-end run has been
recorded since that fix.** The six other rows stand as of 2026-08-20;
the alerting path is unverified against a live deployment.

### CI

Run [32787295183](https://github.com/Bigbadlonewolf/SecureVault/actions/runs/32787295183),
commit `6606415`, 2026-08-24. Three jobs, all success.

| Check | Job | Result |
| --- | --- | --- |
| `pytest` | Python Tests | 62 passed in 1.42s |
| `bandit -r src/ scripts/ -ll` | Security Scan | pass |
| `pip-audit -r src/requirements.txt` | Security Scan | pass |
| Checkov on `terraform/` | Security Scan | pass |
| truffleHog secret scan | Security Scan | pass |
| `terraform fmt -check` and `validate` | Terraform Plan | pass |
| `terraform plan` | Terraform Plan | pass, authenticated by Workload Identity Federation |

The plan step ran for real on this run. Before Workload Identity
Federation landed, `Authenticate to GCP` and `Terraform Plan` were both
skipped for want of a repository secret, and the job reported success on
`fmt`, `init`, and `validate` alone. Confirmed here from the step
conclusions rather than the job badge, because the badge does not
distinguish the two.

## Known Limitations

**Alert delivery is not monitored.** The function logs `Brevo alert
sent` on a 201 from Brevo's API. That confirms acceptance, not
delivery. On 2026-08-20 the API returned 201 for two sends that Brevo
then rejected at send time because the sender domain did not exist —
the logs were clean and nothing arrived. Delivery state lives in
Brevo's event API (`/v3/smtp/statistics/events`), which nothing in
this project polls.

Two failure modes are therefore unmonitored:

1. Brevo re-enables its API-key IP allowlist on credential rotation
   (observed 2026-08-21, see
   [ADR-010](../adr/ADR-010-alerting-source-ip-allowlist.md)) and
   alerting starts returning 401.
2. Brevo accepts a send and rejects it downstream — bad sender,
   suppression list, quota.

Accepted at demo scope. Closing this needs a scheduled job polling
the events API and comparing against findings processed, which is
more infrastructure than the alerting path itself. Revisit if this
pipeline is used outside a demo project.
