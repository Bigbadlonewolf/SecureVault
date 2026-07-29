"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from unittest.mock import MagicMock, patch

from google.api_core.iam import Policy

from scc_processor.processors import remediator
from scc_processor.processors.remediator import remediate


def test_unmapped_critical_returns_skipped_unmapped():
    finding = {
        "name": "projects/test/sources/123/findings/unmapped",
        "findingClass": "MISCONFIGURATION",
        "category": "UNKNOWN_CRITICAL",
        "severity": "CRITICAL",
        "resourceName": "//cloudresourcemanager.googleapis.com/projects/test",
    }
    result = remediate(finding)
    assert result["status"] == "SKIPPED_UNMAPPED"
    assert result["action"] == "NONE"


@patch("scc_processor.processors.remediator.storage")
def test_public_bucket_acl_handler_removes_public_members(mock_storage, env_vars):
    # Use the real google.api_core.iam.Policy so this test fails if the
    # handler calls methods or attributes that do not exist on the real
    # class. version=3 emulates get_iam_policy(requested_policy_version=3),
    # under which dict-style access raises InvalidOperationException.
    policy = Policy(version=3)
    policy.bindings = [
        {
            "role": "roles/storage.objectViewer",
            "members": {
                "allUsers",
                "allAuthenticatedUsers",
                "serviceAccount:keep@test.iam.gserviceaccount.com",
            },
        }
    ]

    bucket = MagicMock()
    bucket.get_iam_policy.return_value = policy

    client = MagicMock()
    client.bucket.return_value = bucket
    mock_storage.Client.return_value = client

    finding = {
        "name": "projects/test/sources/123/findings/public-bucket",
        "findingClass": "MISCONFIGURATION",
        "category": "PUBLIC_BUCKET_ACL",
        "severity": "CRITICAL",
        "resourceName": "//storage.googleapis.com/public-bucket",
    }
    result = remediate(finding)

    assert result["status"] == "SUCCESS"
    assert result["action"] == "PUBLIC_BUCKET_ACL"
    # Public members are removed; unrelated members are retained.
    members_by_role = {b["role"]: b["members"] for b in policy.bindings}
    assert members_by_role["roles/storage.objectViewer"] == {
        "serviceAccount:keep@test.iam.gserviceaccount.com"
    }
    bucket.set_iam_policy.assert_called_once_with(policy)


@patch("scc_processor.processors.remediator.storage")
def test_public_bucket_acl_drops_role_left_with_no_members(mock_storage, env_vars):
    policy = Policy()
    policy.bindings = [
        {"role": "roles/storage.objectViewer", "members": {"allUsers"}}
    ]

    bucket = MagicMock()
    bucket.get_iam_policy.return_value = policy

    client = MagicMock()
    client.bucket.return_value = bucket
    mock_storage.Client.return_value = client

    finding = {
        "name": "projects/test/sources/123/findings/public-bucket-empty",
        "findingClass": "MISCONFIGURATION",
        "category": "PUBLIC_BUCKET_ACL",
        "severity": "CRITICAL",
        "resourceName": "//storage.googleapis.com/public-bucket",
    }
    result = remediate(finding)

    assert result["status"] == "SUCCESS"
    # A binding left with no members is dropped rather than written back empty.
    assert policy.bindings == []
    bucket.set_iam_policy.assert_called_once_with(policy)


@patch("scc_processor.processors.remediator.storage")
def test_public_bucket_acl_skips_when_no_public_members(mock_storage, env_vars):
    policy = Policy()
    policy.bindings = [
        {
            "role": "roles/storage.objectViewer",
            "members": {"serviceAccount:keep@test.iam.gserviceaccount.com"},
        }
    ]

    bucket = MagicMock()
    bucket.get_iam_policy.return_value = policy

    client = MagicMock()
    client.bucket.return_value = bucket
    mock_storage.Client.return_value = client

    finding = {
        "name": "projects/test/sources/123/findings/private-bucket",
        "findingClass": "MISCONFIGURATION",
        "category": "PUBLIC_BUCKET_ACL",
        "severity": "CRITICAL",
        "resourceName": "//storage.googleapis.com/private-bucket",
    }
    result = remediate(finding)

    assert result["status"] == "SKIPPED"
    bucket.set_iam_policy.assert_not_called()


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
        "name": "projects/test/sources/123/findings/open-firewall",
        "findingClass": "MISCONFIGURATION",
        "category": "OPEN_FIREWALL",
        "severity": "CRITICAL",
        "resourceName": "//compute.googleapis.com/projects/test/global/firewalls/allow-all-ssh",
    }
    result = remediate(finding)

    assert result["status"] == "SUCCESS"
    assert result["action"] == "OPEN_FIREWALL"
    firewalls_client.patch.assert_called_once()


@patch("scc_processor.processors.remediator.storage")
def test_handler_error_returns_failure_status(mock_storage, env_vars):
    mock_storage.Client.side_effect = RuntimeError("API unavailable")

    finding = {
        "name": "projects/test/sources/123/findings/public-bucket-fail",
        "findingClass": "MISCONFIGURATION",
        "category": "PUBLIC_BUCKET_ACL",
        "severity": "CRITICAL",
        "resourceName": "//storage.googleapis.com/public-bucket",
    }
    result = remediate(finding)

    assert result["status"] == "FAILURE"
    assert "error" in result


def test_over_privileged_sa_is_not_auto_remediated():
    finding = {
        "name": "projects/test/sources/123/findings/overpriv-sa",
        "findingClass": "MISCONFIGURATION",
        "category": "OVER_PRIVILEGED_SERVICE_ACCOUNT",
        "severity": "CRITICAL",
        "resourceName": "//iam.googleapis.com/projects/test/serviceAccounts/overpriv@test.iam.gserviceaccount.com",
    }
    result = remediate(finding)

    assert result["status"] == "SKIPPED_UNMAPPED"
    assert result["action"] == "NONE"


def test_over_privileged_sa_is_absent_from_the_auto_remediation_map():
    """ADR-004: the class must not be routable, not merely unrouted today.

    The behavioural test above passes for the wrong reason if someone adds the
    class back to _AUTO_REMEDIATION_CLASSES pointing at a no-op. This asserts
    the map itself.
    """
    assert "OVER_PRIVILEGED_SA" not in remediator._AUTO_REMEDIATION_CLASSES


def test_no_service_account_role_handler_is_registered():
    """ADR-004: no handler may strip roles from a service account.

    remove_excess_service_account_roles removed every binding matching
    `roles/` — including the primitives its docstring claimed to keep — because
    SCC's finding never identifies which grant is the excessive one. Re-adding
    any handler that touches service-account roles needs its own ADR first.
    """
    assert not hasattr(remediator, "remove_excess_service_account_roles")

    for handler_name in remediator._AUTO_REMEDIATION_CLASSES.values():
        handler = remediator._get_handler(handler_name)
        assert "service_account" not in handler.__name__
        assert "role" not in handler.__name__
