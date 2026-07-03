# SecureVault Evolution

> This file tracks notable changes and fixes to the SecureVault project.

## 2026-07-03 — TruffleHog CI Fix

**Problem:** `Security Scan` job failed on every push to `main` with:
> BASE and HEAD commits are the same. TruffleHog won't scan anything.

**Root cause:** TruffleHog was configured with `base: main` and `head: HEAD`.
On a `push` event to `main`, both references point to the identical commit,
so there is no diff to scan.

**Fix:**
- Added `fetch-depth: 0` to the checkout step to ensure full Git history is available.
- Changed TruffleHog `base` and `head` inputs to use conditional expressions:
  - `pull_request`: scans diff between base and head branches.
  - `push`: scans full repository history from first commit to HEAD.

**Verification:** CI run passes; TruffleHog completes without "BASE and HEAD are the same" error.
