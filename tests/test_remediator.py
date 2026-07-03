"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from unittest.mock import MagicMock, patch

import pytest

from scc_processor.processors.remediator import remediate


def test_unmapped_critical_returns_skipped_unmapped():
    finding = {
        "findingId": "unmapped",
        "findingClass": "UNKNOWN_CRITICAL",
        "severity": "CRITICAL",
        "resource": "projects/test/resources/unknown",
    }
    result = remediate(finding)
    assert result["status"] == "SKIPPED_UNMAPPED"
    assert result["action"] == "NONE"


@patch("scc_processor.processors.remediator.storage")
def test_public_bucket_acl_handler_removes_public_members(mock_storage, env_vars):
    policy = MagicMock()
    policy.roles = ["roles/storage.objectViewer"]
    policy.has_role.return_value = True

    bucket = MagicMock()
    bucket.get_iam_policy.return_value = policy

    client = MagicMock()
    client.bucket.return_value = bucket
    mock_storage.Client.return_value = client

    finding = {
        "findingId": "public-bucket",
        "findingClass": "PUBLIC_BUCKET_ACL",
        "severity": "CRITICAL",
        "resource": "gs://public-bucket",
    }
    result = remediate(finding)

    assert result["status"] == "SUCCESS"
    assert result["action"] == "PUBLIC_BUCKET_ACL"
    bucket.set_iam_policy.assert_called_once_with(policy)


@patch("scc_processor.processors.remediator.compute_v1")
def test_open_firewall_handler_disables_permissive_rule(mock_compute, env_vars):
    rule = MagicMock()
    rule.disabled = False
    rule.source_ranges = ["0.0.0.0/0"]

    allowed = MagicMock()
    allowed.ports = ["22"]
    rule.allowed = [allowed]

    firewalls_client = MagicMock()
    firewalls_client.get.return_value = rule
    mock_compute.FirewallsClient.return_value = firewalls_client

    finding = {
        "findingId": "open-firewall",
        "findingClass": "OPEN_FIREWALL",
        "severity": "CRITICAL",
        "resource": "projects/test/firewalls/allow-all-ssh",
    }
    result = remediate(finding)

    assert result["status"] == "SUCCESS"
    assert result["action"] == "OPEN_FIREWALL"
    firewalls_client.patch.assert_called_once()


@patch("scc_processor.processors.remediator.storage")
def test_handler_error_returns_failure_status(mock_storage, env_vars):
    mock_storage.Client.side_effect = RuntimeError("API unavailable")

    finding = {
        "findingId": "public-bucket-fail",
        "findingClass": "PUBLIC_BUCKET_ACL",
        "severity": "CRITICAL",
        "resource": "gs://public-bucket",
    }
    result = remediate(finding)

    assert result["status"] == "FAILURE"
    assert "error" in result
