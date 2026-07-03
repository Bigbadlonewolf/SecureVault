# Contributing to SecureVault

> **Author:** Lanre Oluokun  
> **Implementation:** AI-assisted under architect direction  
> **License:** MIT

Thank you for your interest in improving SecureVault. This document explains how to set up a development environment, run tests, propose changes, and stay aligned with the project’s security and cost constraints.

---

## Quickstart

1. **Clone the repository**
   ```bash
   git clone https://github.com/Bigbadlonewolf/SecureVault.git
   cd SecureVault
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r src/requirements.txt
   pip install pytest bandit pip-audit checkov trufflehog
   ```

3. **Run the test suite**
   ```bash
   make test
   ```

4. **Run security scans**
   ```bash
   make security
   ```

5. **Validate Terraform**
   ```bash
   make terraform-plan
   ```

---

## Development Standards

### Code Style

- **Python:** Follow PEP 8. Use type hints for public function signatures.
- **Terraform:** Run `terraform fmt -recursive` before committing.
- **Imports:** Group standard library, third-party, and local imports with a blank line between groups.
- **Naming:** Use `snake_case` for Python functions and variables, `PascalCase` for classes, and descriptive Terraform resource names.

### Documentation

- Every new module, ADR, or major change must update the relevant document in `docs/`, `context/`, or `adr/`.
- Keep `README.md` and `EVOLUTION.md` in sync with new capabilities.

### Attribution Header

New Python and Terraform files should include the standard header:

```python
"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""
```

```hcl
# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT
```

---

## Testing

SecureVault uses `pytest` with heavy mocking for GCP and Brevo APIs.

```bash
pytest -q
```

### Test Structure

| File | Purpose |
|---|---|
| `tests/test_main.py` | Entry-point orchestration and Pub/Sub parsing |
| `tests/test_classifier.py` | Severity classification and overrides |
| `tests/test_remediator.py` | Auto-remediation handlers and failure modes |
| `tests/test_notifier.py` | Brevo email alerting and Secret Manager integration |
| `tests/test_integration.py` | End-to-end flow with mocked dependencies |
| `tests/conftest.py` | Shared fixtures and environment setup |

### Adding Tests

- Mock external services; do not require real GCP credentials for unit tests.
- Use descriptive test names that explain the behavior being verified.
- Ensure new code paths are covered by at least one test.

---

## Security

Security is the top priority. Every pull request must pass:

```bash
make security
```

This runs:

- `bandit -r src/ -ll` — Python SAST
- `pip-audit -r src/requirements.txt --desc` — dependency vulnerability scan
- `checkov -d terraform/ --framework terraform` — Terraform/IaC misconfiguration scan
- `trufflehog filesystem . --only-verified` — secret detection

### Security Review Checklist

- [ ] No secrets, API keys, or credentials in code or tests.
- [ ] New IAM permissions are justified and documented in the ADR or PR description.
- [ ] New auto-remediation handlers include failure handling and rollback notes.
- [ ] New dependencies are pinned and audited.

---

## Pull Request Process

1. **Open an issue first** for significant changes (new remediation handlers, architectural changes, new integrations).
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-change-name
   ```
3. **Make focused commits** with clear messages:
   ```text
   feat: add open Cloud SQL auto-remediation handler

   - Adds Cloud SQL instance remediation to remove 0.0.0.0/0 authorized networks
   - Includes unit tests and rollback procedure
   - Updates ADR-004 and operations runbook
   ```
4. **Run the full local validation**:
   ```bash
   make test
   make security
   make terraform-plan
   ```
5. **Open a pull request** against `main`.
6. **Wait for CI to pass** and address reviewer feedback.

All changes require review by `@Bigbadlonewolf` per [`CODEOWNERS`](.github/CODEOWNERS).

---

## Reporting Security Issues

Please do not open public issues for security vulnerabilities. Email **Lanreoluokunigbadwolf@gmail.com** or open a private security advisory on GitHub.

---

## Cost-Conscious Changes

SecureVault’s operating cost target is under **$5/month**. Before proposing a change that increases cost, include a brief cost impact estimate:

- New GCP service? Estimate monthly cost at 10,000 findings/month.
- Higher memory or longer timeout? Show the GB-second impact.
- New dependency? Note any paid API calls.

See [`context/COST_ANALYSIS.md`](context/COST_ANALYSIS.md) for the current model.

---

## Code of Conduct

- Be respectful and constructive.
- Focus feedback on the design, code, or documentation — not the person.
- Assume good intent.
- Harassment, discrimination, or toxic behavior will not be tolerated.

---

## Questions?

Open a [discussion](https://github.com/Bigbadlonewolf/SecureVault/discussions) or reach out via email.
