"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import importlib.util
from pathlib import Path

import pytest

# scripts/ is not a package and is not on sys.path, so load the module by path.
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "simulate_finding.py"
_spec = importlib.util.spec_from_file_location("simulate_finding", SCRIPT)
simulate_finding = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(simulate_finding)

MAPPED_CLASSES = ["PUBLIC_BUCKET_ACL", "OPEN_FIREWALL", "OVER_PRIVILEGED_SA", "PUBLIC_DATASET"]


@pytest.mark.parametrize("finding_class", MAPPED_CLASSES)
def test_the_requested_project_reaches_every_addressed_field(finding_class, monkeypatch):
    """Regression: _sample_finding read PROJECT_ID from the environment and
    ignored --project, so findings were addressed to 'unknown-project' while
    being published to the real one. Remediation could only ever 404."""
    monkeypatch.delenv("PROJECT_ID", raising=False)

    finding = simulate_finding._sample_finding(finding_class, "CRITICAL", "securevault-demo")

    assert "unknown-project" not in str(finding)
    for field in ("name", "parent", "resourceName"):
        assert "securevault-demo" in finding[field]


def test_the_environment_does_not_override_the_argument(monkeypatch):
    monkeypatch.setenv("PROJECT_ID", "some-other-project")

    finding = simulate_finding._sample_finding("PUBLIC_BUCKET_ACL", "CRITICAL", "securevault-demo")

    assert "some-other-project" not in str(finding)
    assert finding["resourceName"] == "//storage.googleapis.com/securevault-demo-public-bucket"


def test_the_bucket_resource_name_matches_what_the_remediator_parses():
    """remediator._extract_bucket_name strips the //storage.googleapis.com/
    prefix, so the simulated name must carry it."""
    from scc_processor.processors.remediator import _extract_bucket_name

    finding = simulate_finding._sample_finding("PUBLIC_BUCKET_ACL", "CRITICAL", "securevault-demo")

    assert _extract_bucket_name(finding["resourceName"]) == "securevault-demo-public-bucket"
