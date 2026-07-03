"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import os
from typing import Any, Dict

import requests

from scc_processor.utils.config_loader import load_config
from scc_processor.utils.logger import get_logger

_logger = get_logger()


def send_alert(finding: Dict[str, Any], action_result: Dict[str, Any]) -> bool:
    """Send a Brevo email alert for a finding.

    Args:
        finding: The SCC finding payload.
        action_result: The result returned by the remediator, including action and status.

    Returns:
        True if the alert was accepted by Brevo, False otherwise.
    """
    try:
        config = load_config()
        brevo_config = config.get("brevo", {})
        api_url = brevo_config.get("api_url", "https://api.brevo.com/v3/smtp/email")
        sender_email = brevo_config.get("sender_email", "securevault@lanreoluokun.com")
        sender_name = brevo_config.get("sender_name", "SecureVault Alerts")

        alert_email = os.environ.get("ALERT_EMAIL")
        if not alert_email:
            _logger.error("ALERT_EMAIL environment variable is not set")
            return False

        api_key = _get_brevo_api_key()
        if not api_key:
            _logger.error("Brevo API key is empty or unavailable")
            return False

        severity = finding.get("severity", "UNKNOWN")
        finding_class = finding.get("findingClass", "UNKNOWN")
        resource = finding.get("resource", "UNKNOWN")

        subject = f"[SecureVault] {severity}: {finding_class} on {resource}"

        remediation_status = action_result.get("status", "Manual review required")
        remediation_action = action_result.get("action", "N/A")
        resource_link = finding.get("resourceLink", "")

        body = f"""SecureVault detected a {severity} security finding.

Finding class: {finding_class}
Resource: {resource}
Severity: {severity}
Remediation action: {remediation_action}
Remediation status: {remediation_status}
Resource link: {resource_link or "Not available"}
Timestamp: {finding.get('createTime', 'Unknown')}

This alert was generated automatically by SecureVault.
"""

        payload = {
            "sender": {"email": sender_email, "name": sender_name},
            "to": [{"email": alert_email}],
            "subject": subject,
            "textContent": body,
        }

        response = requests.post(
            api_url,
            headers={
                "accept": "application/json",
                "api-key": api_key,
                "content-type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        response.raise_for_status()

        _logger.info(
            "Brevo alert sent",
            extra={
                "finding_id": finding.get("findingId", ""),
                "severity": severity,
                "recipient": alert_email,
                "status_code": response.status_code,
            },
        )
        return True
    except requests.RequestException as exc:
        _logger.error(
            "Brevo alert request failed",
            extra={"finding_id": finding.get("findingId", ""), "error": str(exc)},
        )
        return False
    except Exception as exc:  # pylint: disable=broad-except
        _logger.critical(
            "Unexpected error sending Brevo alert",
            extra={"finding_id": finding.get("findingId", ""), "error": str(exc)},
        )
        return False


def _get_brevo_api_key() -> str:
    """Return the Brevo API key injected by Cloud Functions secret_environment_variables."""
    api_key = os.environ.get("BREVO_API_KEY", "")
    if not api_key:
        _logger.error("BREVO_API_KEY environment variable is not set")
    return api_key
