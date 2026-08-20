"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import os
from typing import Any, Dict

import requests

from scc_processor.processors.classifier import _extract_finding_class
from scc_processor.utils.config_loader import load_config
from scc_processor.utils.logger import get_logger

_logger = get_logger()

# Prefix of a Brevo SMTP relay key, which the v3 REST API does not accept.
_SMTP_KEY_PREFIX = "xsmtpsib-"


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
        finding_class = _extract_finding_class(finding)
        resource = finding.get("resourceName", "UNKNOWN")
        finding_name = finding.get("name", "")

        subject = f"[SecureVault] {severity}: {finding_class} on {resource}"

        remediation_status = action_result.get("status", "Manual review required")
        remediation_action = action_result.get("action", "N/A")

        body = f"""SecureVault detected a {severity} security finding.

Finding class: {finding_class}
Resource: {resource}
Severity: {severity}
Remediation action: {remediation_action}
Remediation status: {remediation_status}
Finding: {finding_name or "Not available"}
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
                "finding_id": finding.get("name", ""),
                "severity": severity,
                "recipient": alert_email,
                "status_code": response.status_code,
            },
        )
        return True
    except requests.RequestException as exc:
        _logger.error(
            "Brevo alert request failed",
            extra={"finding_id": finding.get("name", ""), "error": str(exc)},
        )
        return False
    except Exception as exc:  # pylint: disable=broad-except
        _logger.critical(
            "Unexpected error sending Brevo alert",
            extra={"finding_id": finding.get("name", ""), "error": str(exc)},
        )
        return False


def _get_brevo_api_key() -> str:
    """Return the Brevo API key injected by Cloud Functions secret_environment_variables.

    Secret Manager stores a payload byte for byte, so a version added with
    ``echo`` rather than ``printf '%s'`` carries a trailing newline. Brevo
    rejects the resulting api-key header with a 401 that is indistinguishable
    from a revoked key, so the value is stripped before use.
    """
    api_key = os.environ.get("BREVO_API_KEY", "").strip()
    if not api_key:
        _logger.error("BREVO_API_KEY environment variable is not set")
        return ""

    # Brevo issues two unrelated credentials. SMTP relay keys (xsmtpsib-)
    # authenticate against smtp-relay.brevo.com; the v3 REST endpoint used here
    # accepts only API keys (xkeysib-) and answers anything else with a bare
    # 401, indistinguishable from a revoked key.
    if api_key.startswith(_SMTP_KEY_PREFIX):
        _logger.error(
            "BREVO_API_KEY holds an SMTP relay key, not a v3 API key. The REST "
            "endpoint rejects it with 401. Generate an API key under "
            "Brevo > SMTP & API > API Keys and store that instead."
        )
        return ""

    return api_key
