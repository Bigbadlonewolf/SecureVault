"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import base64
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict

from cloudevents.http import CloudEvent

from scc_processor.processors.classifier import classify_finding, _extract_finding_class
from scc_processor.processors.notifier import send_alert
from scc_processor.processors.remediator import remediate
from scc_processor.storage.bigquery_client import stream_finding
from scc_processor.storage.firestore_client import log_action
from scc_processor.utils.config_loader import load_config
from scc_processor.utils.logger import get_logger

_logger = get_logger()


def process_scc_finding(cloud_event: CloudEvent) -> str:
    """Cloud Function entry point for processing an SCC finding from Pub/Sub.

    Gen 2 functions receive Eventarc events as a single CloudEvent argument.
    For the ``google.cloud.pubsub.topic.v1.messagePublished`` event type,
    ``cloud_event.data`` carries the Pub/Sub message payload.

    Args:
        cloud_event: The CloudEvent delivered by Eventarc.

    Returns:
        "OK" on success. Unhandled exceptions propagate so Eventarc retries.
    """
    correlation_id = str(cloud_event.get("id", "unknown"))
    _logger.info("Received Pub/Sub message", extra={"correlation_id": correlation_id})

    finding = _parse_finding(cloud_event)
    finding_id = finding.get("name", "unknown")
    resource = finding.get("resourceName", "unknown")
    resource_type = _derive_resource_type(resource)
    finding_class = _extract_finding_class(finding)
    project_id = _extract_project_id(finding)

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


def _parse_finding(cloud_event: CloudEvent) -> Dict[str, Any]:
    """Decode and parse the Pub/Sub message payload into a finding dictionary."""
    data = cloud_event.data or {}
    message = data.get("message") or {}
    encoded = message.get("data")
    if not encoded:
        raise ValueError("Pub/Sub CloudEvent missing 'message.data' field")

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


def _extract_project_id(finding: Dict[str, Any]) -> str:
    """Derive the GCP project ID for a finding.

    Real SCC findings carry no top-level projectId. The project is taken from
    sourceProperties when the detector provides it, otherwise parsed from the
    resourceName or finding name (``.../projects/<project>/...``). Falls back
    to the function's own PROJECT_ID environment variable.
    """
    source_properties = finding.get("sourceProperties")
    if isinstance(source_properties, dict):
        for key in ("projectId", "project_id", "ProjectId"):
            value = source_properties.get(key)
            if isinstance(value, str) and value:
                return value

    for field in (finding.get("resourceName", ""), finding.get("name", "")):
        match = re.search(r"projects/([^/]+)", str(field))
        if match:
            return match.group(1)

    return os.environ.get("PROJECT_ID", "unknown")


# Cloud Asset collection path segments mapped to their resource type kind.
_COLLECTION_KIND_MAP = {
    "buckets": "Bucket",
    "firewalls": "Firewall",
    "serviceAccounts": "ServiceAccount",
    "instances": "Instance",
    "datasets": "Dataset",
}


def _derive_resource_type(resource_name: str) -> str:
    """Derive a resource type from a Cloud Asset-style resourceName.

    Examples:
        //storage.googleapis.com/my-bucket -> storage.googleapis.com/Bucket
        //compute.googleapis.com/projects/p/global/firewalls/fw -> compute.googleapis.com/Firewall
    """
    if not isinstance(resource_name, str) or not resource_name.startswith("//"):
        return "unknown"

    parts = resource_name[2:].split("/")
    service = parts[0]
    for segment in parts[1:-1]:
        kind = _COLLECTION_KIND_MAP.get(segment)
        if kind:
            return f"{service}/{kind}"

    # Buckets sit directly under the service with no collection segment.
    if service == "storage.googleapis.com" and len(parts) == 2:
        return "storage.googleapis.com/Bucket"
    return service
