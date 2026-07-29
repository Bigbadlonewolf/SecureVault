# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

Cloud-native security detection and response pipeline on GCP: consumes Security Command Center findings via Pub/Sub, classifies severity in a Cloud Function (Gen 2, Python 3.11, `src/scc_processor/`), auto-remediates critical mapped findings, alerts via Brevo on high, logs everything to Firestore/BigQuery for audit. Infra in `terraform/`; full architecture in `README.md`.

Commands via `Makefile`: `make test` (pytest), `make security` (bandit, pip-audit, Checkov, truffleHog), `make terraform-plan`, `make simulate-finding`. The suite runs from `.venv/` — `python -m pytest` against the system interpreter fails on missing `google-cloud-*` packages.

Targets real GCP. Confirm with the user before `make terraform-apply`, `make deploy`, or any destructive cloud action; never weaken a security control to make local work easier; never commit secrets — use Secret Manager. Workspace-wide rules are in the root `CLAUDE.md` § Security defaults.

## Two deliberate absences

Both are guarded by tests. Read the ADR before filling either gap.

- **No auto-remediation for `OVER_PRIVILEGED_SA`.** SCC's finding does not identify *which* grant is excessive, so any handler could only strip every `roles/*` binding — including primitives — on a CRITICAL trigger with no human in the loop. ADR-004. The handler existed as dead code until v0.1.4 and was removed; `test_no_service_account_role_handler_is_registered` stops it coming back.
- **No VPC, connector, Cloud Router, or Cloud NAT.** ADR-009 removed them: the VPC held no resources, so the connector routed egress into an empty network and out again through NAT, at a pinned two-instance floor. `ingress_settings = "ALLOW_INTERNAL_ONLY"` is independent of this and stays.

## Watch for

Documents in this repo have drifted from the code more than once, in both directions — `FIXES.md` once claimed resources that did not exist, and ADR-009 was `Accepted` for a week while the resources it removed were still in `main.tf`. When a doc and `terraform/` disagree, check `git show HEAD:terraform/main.tf` before believing either.
