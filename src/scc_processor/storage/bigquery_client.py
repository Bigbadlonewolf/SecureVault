"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import os
from datetime import datetime, timezone
from typing import Optional

from google.cloud import bigquery

from scc_processor.utils.logger import get_logger

_logger = get_logger()


def stream_finding(
    finding_id: str,
    timestamp: datetime,
    resource_type: str,
    resource_name: str,
    severity: str,
    finding_class: str,
    action: str,
    project_id: str,
    status: str,
    error: Optional[str] = None,
) -> bool:
    """Stream a processed finding into BigQuery for historical analytics.

    Args:
        finding_id: Unique SCC finding identifier.
        timestamp: Time the finding was processed.
        resource_type: GCP resource type affected by the finding.
        resource_name: Full resource name of the affected asset.
        severity: SecureVault severity level.
        finding_class: Mapped finding class for response routing.
        action: Action taken.
        project_id: GCP project ID where the finding originated.
        status: Outcome status.
        error: Optional error message.

    Returns:
        True if the streaming insert succeeded, False otherwise.
    """
    try:
        client = bigquery.Client()
        dataset = os.environ.get("BIGQUERY_DATASET", "securevault_analytics")
        table = os.environ.get("BIGQUERY_TABLE", "findings_history")
        table_ref = f"{client.project}.{dataset}.{table}"

        row = {
            "finding_id": finding_id,
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "resource_type": resource_type,
            "resource_name": resource_name,
            "severity": severity,
            "finding_class": finding_class,
            "action": action,
            "project_id": project_id,
            "status": status,
            "error": error,
        }

        errors = client.insert_rows_json(table_ref, [row])
        if errors:
            _logger.error(
                "BigQuery streaming insert returned errors",
                extra={"finding_id": finding_id, "errors": str(errors)},
            )
            return False

        _logger.info(
            "Finding streamed to BigQuery",
            extra={"finding_id": finding_id, "table": table_ref},
        )
        return True
    except Exception as exc:  # pylint: disable=broad-except
        _logger.error(
            "Failed to stream finding to BigQuery",
            extra={"finding_id": finding_id, "error": str(exc)},
        )
        return False
