"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

from scc_processor.processors.classifier import classify_finding, _extract_finding_class
from scc_processor.processors.notifier import send_alert
from scc_processor.processors.remediator import remediate
from scc_processor.storage.bigquery_client import stream_finding
from scc_processor.storage.firestore_client import log_action
from scc_processor.utils.config_loader import load_config
from scc_processor.utils.logger import get_logger

_logger = get_logger()


def process_scc_finding(event: Dict[str, Any], context: Any) -> str:
    """Cloud Function entry point for processing an SCC finding from Pub/Sub.

    Args:
        event: The Pub/Sub event payload.
        context: The Cloud Functions runtime context.

    Returns:
        "OK" on success. Unhandled exceptions propagate as 500 responses.
    """
    correlation_id = getattr(context, "event_id", "unknown")
    _logger.info("Received Pub/Sub message", extra={"correlation_id": correlation_id})

    finding = _parse_finding(event)
    finding_id = finding.get("findingId", "unknown")
    resource = finding.get("resource", "unknown")
    resource_type = finding.get("resourceType", "unknown")
    finding_class = _extract_finding_class(finding)
    project_id = finding.get("projectId", os.environ.get("PROJECT_ID", "unknown"))

    # Attach correlation ID to all downstream log records.
    extra = {"correlation_id": correlation_id, "finding_id": finding_id}
    _logger.info("Processing finding", extra=extra)

    severity = classify_finding(finding)
    config = load_config()
    response_matrix = config["response_matrix"]

    action_result: Dict[str, Any] = {"action": "NONE", "status": "PENDING"}
    alert_sent = False

    if severity == "CRITICAL":
        auto_remediate_classes = response_matrix["CRITICAL"].get("auto_remediate", [])
        if finding_class in auto_remediate_classes:
            action_result = remediate(finding)
            alert_sent = send_alert(finding, action_result)
        else:
            action_result = {
                "action": "NONE",
                "status": "SKIPPED_UNMAPPED",
                "message": "CRITICAL finding not in auto-remediation list",
            }
            alert_sent = send_alert(finding, action_result)
    elif severity == "HIGH":
        action_result = {"action": "ALERT", "status": "SUCCESS"}
        alert_sent = send_alert(finding, action_result)
    elif severity == "MEDIUM":
        action_result = {"action": "LOG", "status": "SUCCESS"}
        _logger.info("MEDIUM severity finding logged for digest", extra=extra)
    else:
        action_result = {"action": "LOG", "status": "SUCCESS"}
        _logger.info("LOW severity finding logged for digest", extra=extra)

    # Persist operational state and analytics regardless of alerting outcome.
    log_action(
        finding_id=finding_id,
        resource=resource,
        severity=severity,
        action=action_result.get("action", "NONE"),
        status=action_result.get("status", "UNKNOWN"),
        error=action_result.get("error"),
    )

    stream_finding(
        finding_id=finding_id,
        timestamp=datetime.now(timezone.utc),
        resource_type=resource_type,
        resource_name=resource,
        severity=severity,
        finding_class=finding_class,
        action=action_result.get("action", "NONE"),
        project_id=project_id,
        status=action_result.get("status", "UNKNOWN"),
        error=action_result.get("error"),
    )

    _logger.info(
        "Finding processing complete",
        extra={
            **extra,
            "finding_severity": severity,
            "finding_class": finding_class,
            "action": action_result.get("action", "NONE"),
            "status": action_result.get("status", "UNKNOWN"),
            "alert_sent": alert_sent,
        },
    )

    return "OK"


def _parse_finding(event: Dict[str, Any]) -> Dict[str, Any]:
    """Decode and parse the Pub/Sub message payload into a finding dictionary."""
    if "data" not in event:
        raise ValueError("Pub/Sub event missing 'data' field")

    encoded = event["data"]
    decoded = base64.b64decode(encoded).decode("utf-8")
    payload = json.loads(decoded)

    # SCC notifications wrap the finding in a "finding" key.
    if "finding" in payload:
        finding = payload["finding"]
    else:
        finding = payload

    if not isinstance(finding, dict):
        raise ValueError("Parsed finding is not a dictionary")

    return finding
