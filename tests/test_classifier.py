"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import pytest

from scc_processor.processors.classifier import classify_finding


@pytest.fixture
def base_finding():
    return {
        "name": "projects/test/sources/123/findings/test",
        "findingClass": "MISCONFIGURATION",
        "category": "AUDIT_LOGGING_DISABLED",
        "resourceName": "//cloudresourcemanager.googleapis.com/projects/test",
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
        "name": "projects/test/sources/123/findings/override",
        "findingClass": "MISCONFIGURATION",
        "category": "PUBLIC_BUCKET_ACL",
        "severity": "HIGH",
        "resourceName": "//storage.googleapis.com/public-bucket",
    }
    assert classify_finding(finding) == "CRITICAL"


def test_classify_override_elevates_open_firewall_to_critical():
    finding = {
        "name": "projects/test/sources/123/findings/override",
        "findingClass": "MISCONFIGURATION",
        "category": "OPEN_FIREWALL",
        "severity": "MEDIUM",
        "resourceName": "//compute.googleapis.com/projects/test/global/firewalls/allow-all",
    }
    assert classify_finding(finding) == "CRITICAL"


def test_classify_unknown_severity_defaults_to_medium(base_finding):
    base_finding["severity"] = "UNEXPECTED_VALUE"
    assert classify_finding(base_finding) == "MEDIUM"


def test_classify_unspecified_severity_defaults_to_medium(base_finding):
    base_finding["severity"] = "SEVERITY_UNSPECIFIED"
    assert classify_finding(base_finding) == "MEDIUM"
