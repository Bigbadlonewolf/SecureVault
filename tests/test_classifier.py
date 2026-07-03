"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import pytest

from processors.classifier import classify_finding


@pytest.fixture
def base_finding():
    return {
        "findingId": "test",
        "findingClass": "UNUSED_SERVICE_ACCOUNT",
        "category": "SERVICE_ACCOUNT",
        "resource": "projects/test/serviceAccounts/unused@test.iam.gserviceaccount.com",
    }


def test_classify_critical(base_finding):
    base_finding["severity"] = "CRITICAL"
    assert classify_finding(base_finding) == "CRITICAL"


def test_classify_high(base_finding):
    base_finding["severity"] = "HIGH"
    assert classify_finding(base_finding) == "HIGH"


def test_classify_medium(base_finding):
    base_finding["severity"] = "MEDIUM"
    assert classify_finding(base_finding) == "MEDIUM"


def test_classify_override_elevates_public_bucket_to_critical():
    finding = {
        "findingId": "override",
        "findingClass": "PUBLIC_BUCKET_ACL",
        "category": "STORAGE_BUCKET_PUBLIC",
        "severity": "HIGH",
        "resource": "gs://public-bucket",
    }
    assert classify_finding(finding) == "CRITICAL"


def test_classify_unknown_severity_defaults_to_medium(base_finding):
    base_finding["severity"] = "UNEXPECTED_VALUE"
    assert classify_finding(base_finding) == "MEDIUM"


def test_classify_unspecified_severity_defaults_to_medium(base_finding):
    base_finding["severity"] = "SEVERITY_UNSPECIFIED"
    assert classify_finding(base_finding) == "MEDIUM"
