"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import os
from typing import Any, Callable, Dict, List

from google.cloud import compute_v1, resourcemanager_v3, storage

from scc_processor.processors.classifier import _extract_finding_class
from scc_processor.utils.logger import get_logger

_logger = get_logger()

# Finding classes eligible for auto-remediation.
# OVER_PRIVILEGED_SA is intentionally excluded: SCC does not identify the
# specific excessive role, so unattended revocation of all roles is unsafe.
_AUTO_REMEDIATION_CLASSES = {
    "PUBLIC_BUCKET_ACL": "remove_public_bucket_access",
    "OPEN_FIREWALL": "disable_open_firewall_rule",
}

# IAM members that make a Cloud Storage bucket publicly accessible.
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


def remediate(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the appropriate remediation handler for a finding.

    Args:
        finding: The SCC finding payload.

    Returns:
        A dictionary describing the action taken and its status.
    """
    finding_class = _extract_finding_class(finding)
    if finding_class not in _AUTO_REMEDIATION_CLASSES:
        return {
            "action": "NONE",
            "status": "SKIPPED_UNMAPPED",
            "finding_class": finding_class,
        }

    handler_name = _AUTO_REMEDIATION_CLASSES[finding_class]
    handler = _get_handler(handler_name)

    try:
        return handler(finding)
    except Exception as exc:  # pylint: disable=broad-except
        _logger.error(
            "Remediation handler failed",
            extra={
                "finding_id": finding.get("name", ""),
                "finding_class": finding_class,
                "error": str(exc),
            },
        )
        return {
            "action": finding_class,
            "status": "FAILURE",
            "error": str(exc),
            "finding_class": finding_class,
        }


def _get_handler(name: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Return the remediation handler function by name."""
    handlers = {
        "remove_public_bucket_access": remove_public_bucket_access,
        "disable_open_firewall_rule": disable_open_firewall_rule,
        "remove_excess_service_account_roles": remove_excess_service_account_roles,
    }
    return handlers[name]


def remove_public_bucket_access(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Remove allUsers and allAuthenticatedUsers from a Cloud Storage bucket IAM policy."""
    resource = finding.get("resourceName", "")
    bucket_name = _extract_bucket_name(resource)
    project_id = os.environ.get("PROJECT_ID")

    if not bucket_name or not project_id:
        return {
            "action": "PUBLIC_BUCKET_ACL",
            "status": "FAILURE",
            "error": "Missing bucket name or PROJECT_ID",
        }

    client = storage.Client(project=project_id)
    bucket = client.bucket(bucket_name)
    policy = bucket.get_iam_policy(requested_policy_version=3)

    # google.api_core.iam.Policy exposes bindings as a list of
    # {"role": ..., "members": {...}} dicts. This is the documented,
    # policy-version-safe access path: dict-style access (policy[role])
    # raises InvalidOperationException on version 3 policies, which
    # requested_policy_version=3 can return.
    removed = False
    kept = []
    for binding in policy.bindings:
        members = set(binding.get("members") or ())
        updated = members - _PUBLIC_MEMBERS
        if len(updated) != len(members):
            removed = True
        if updated:
            binding["members"] = updated
            kept.append(binding)

    if not removed:
        return {
            "action": "PUBLIC_BUCKET_ACL",
            "status": "SKIPPED",
            "message": "No public members found on bucket",
        }

    # Drop bindings left with no members and write the policy back.
    policy.bindings = kept
    bucket.set_iam_policy(policy)
    _logger.info(
        "Removed public access from bucket",
        extra={"finding_id": finding.get("name", ""), "bucket": bucket_name},
    )
    return {"action": "PUBLIC_BUCKET_ACL", "status": "SUCCESS"}


def disable_open_firewall_rule(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Disable a Compute Engine firewall rule that allows 0.0.0.0/0 on sensitive ports."""
    resource = finding.get("resourceName", "")
    project_id = os.environ.get("PROJECT_ID")
    firewall_name = _extract_firewall_name(resource)

    if not firewall_name or not project_id:
        return {
            "action": "OPEN_FIREWALL",
            "status": "FAILURE",
            "error": "Missing firewall name or PROJECT_ID",
        }

    client = compute_v1.FirewallsClient()
    rule = client.get(project=project_id, firewall=firewall_name)

    # Only disable rules that are currently enabled and overly permissive.
    if not rule.disabled and _is_overly_permissive(rule):
        patch = compute_v1.Firewall(disabled=True)
        client.patch(project=project_id, firewall=firewall_name, firewall_resource=patch)
        _logger.info(
            "Disabled open firewall rule",
            extra={
                "finding_id": finding.get("name", ""),
                "firewall": firewall_name,
            },
        )
        return {"action": "OPEN_FIREWALL", "status": "SUCCESS"}

    return {
        "action": "OPEN_FIREWALL",
        "status": "SKIPPED",
        "message": "Rule already disabled or not overly permissive",
    }


def remove_excess_service_account_roles(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Remove excess predefined roles from a service account while retaining custom roles."""
    resource = finding.get("resourceName", "")
    project_id = os.environ.get("PROJECT_ID")
    service_account_email = _extract_service_account_email(resource)

    if not project_id:
        return {
            "action": "OVER_PRIVILEGED_SA",
            "status": "FAILURE",
            "error": "Missing PROJECT_ID",
        }

    client = resourcemanager_v3.ProjectsClient()
    project_name = f"projects/{project_id}"

    policy = client.get_iam_policy(request={"resource": project_name})

    modified = False
    for binding in policy.bindings:
        if not binding.members:
            continue
        if service_account_email and service_account_email not in binding.members:
            continue
        if binding.role and binding.role.startswith("roles/"):
            # Remove predefined roles; retain custom roles and primitive roles.
            members_to_remove = [
                m
                for m in binding.members
                if (not service_account_email or m == service_account_email)
                and _is_predefined_role(binding.role)
            ]
            for member in members_to_remove:
                binding.members.remove(member)
                modified = True

    if modified:
        client.set_iam_policy(request={"resource": project_name, "policy": policy})
        _logger.info(
            "Removed excess predefined roles",
            extra={
                "finding_id": finding.get("name", ""),
                "service_account": service_account_email or "all",
            },
        )
        return {"action": "OVER_PRIVILEGED_SA", "status": "SUCCESS"}

    return {
        "action": "OVER_PRIVILEGED_SA",
        "status": "SKIPPED",
        "message": "No excess predefined roles found",
    }


def _extract_bucket_name(resource: str) -> str:
    """Extract the bucket name from a GCP resource identifier."""
    if resource.startswith("gs://"):
        return resource.replace("gs://", "").split("/")[0]
    if "buckets/" in resource:
        return resource.split("buckets/")[-1].split("/")[0]
    if resource.startswith("//storage.googleapis.com/"):
        return resource[len("//storage.googleapis.com/"):].split("/")[0]
    return resource


def _extract_firewall_name(resource: str) -> str:
    """Extract the firewall rule name from a GCP resource identifier."""
    if "firewalls/" in resource:
        return resource.split("firewalls/")[-1].split("/")[0]
    return resource


def _extract_service_account_email(resource: str) -> str:
    """Extract a service account email from a GCP resource identifier."""
    if "serviceAccounts/" in resource:
        return resource.split("serviceAccounts/")[-1].split("/")[0]
    return resource


def _is_overly_permissive(rule: compute_v1.Firewall) -> bool:
    """Return True if the firewall rule allows 0.0.0.0/0 on sensitive ports."""
    if not rule.source_ranges:
        return False
    if "0.0.0.0/0" not in rule.source_ranges:
        return False

    sensitive_ports = {"22", "23", "3389", "3306", "5432", "1433", "27017"}
    allowed_ports: List[str] = []
    for allowed in rule.allowed:
        if allowed.ports:
            allowed_ports.extend(allowed.ports)
        else:
            # No ports specified means all ports for the protocol.
            return True

    return any(port in sensitive_ports for port in allowed_ports)


def _is_predefined_role(role: str) -> bool:
    """Return True if the role is a GCP predefined role (roles/<name>)."""
    return role.startswith("roles/")
