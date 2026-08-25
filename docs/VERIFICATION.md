# Verification

What has been checked against a live deployment, and what has not. A claim
in this repo is either traceable to an entry here or it is untested.

## Evidence

### Pipeline, end to end

Last recorded full trace: `scripts/simulate_finding.py` against
`securevault-demo`, 2026-08-24, message ID `21082942597874403`,
revision `scc-processor-00013-mqt`. Every leg passed.

| Step | Result | Evidence |
| --- | --- | --- |
| Pub/Sub receive | OK | Log `Received Pub/Sub message`, correlation id `21082942597874403` |
| Processing finding | OK | Log `Processing finding` |
| Remediation handler | OK | Log `Disabled open firewall rule`; `gcloud compute firewall-rules describe allow-all-ssh` returns `disabled: True`, `sourceRanges` unchanged at `0.0.0.0/0` |
| Brevo alert | OK | `/v3/smtp/statistics/events` shows `requests` → `delivered` → `opened`, 18:04 EDT |
| Firestore action log | OK | Log `Firestore action logged`, status SUCCESS |
| BigQuery stream | OK | Log `Finding streamed to BigQuery`, table `securevault_analytics.findings_history` |
| Processing complete | OK | Log `Finding processing complete` |

Remediation disables the offending rule rather than narrowing it — the
source range is unchanged after the handler runs. That is the designed
action, not a partial fix.

To reproduce: create a firewall rule allowing `tcp:22` from `0.0.0.0/0`,
run `python scripts/simulate_finding.py --project <PROJECT>
--finding-class OPEN_FIREWALL --severity HIGH`, then check the rule's
`disabled` field and Brevo's events endpoint.

The 2026-08-20 run of this pipeline failed on the alerting leg. Two
faults were involved: a source-IP allowlist
([ADR-010](../adr/ADR-010-alerting-source-ip-allowlist.md)) and a sender
domain that did not exist, fixed in `3c96a47`. The trace above is the
first full-path run after both.

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
