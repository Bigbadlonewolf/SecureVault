"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from typing import Optional

from google.cloud import firestore

from utils.logger import get_logger

_logger = get_logger()


def log_action(
    finding_id: str,
    resource: str,
    severity: str,
    action: str,
    status: str,
    error: Optional[str] = None,
) -> bool:
    """Persist a remediation action to Firestore for fast operational state lookups.

    Args:
        finding_id: Unique SCC finding identifier; used as the document ID.
        resource: Affected GCP resource name or identifier.
        severity: SecureVault severity level.
        action: Action taken (REMEDIATE, ALERT, LOG, etc.).
        status: Outcome status (SUCCESS, FAILURE, SKIPPED).
        error: Optional error message when status is FAILURE.

    Returns:
        True if the write succeeded, False otherwise.
    """
    try:
        client = firestore.Client()
        doc_ref = client.collection("remediation_log").document(finding_id)
        payload = {
            "finding_id": finding_id,
            "resource": resource,
            "severity": severity,
            "action": action,
            "status": status,
            "error": error,
            "processedAt": firestore.SERVER_TIMESTAMP,
        }
        doc_ref.set(payload)
        _logger.info(
            "Firestore action logged",
            extra={
                "finding_id": finding_id,
                "resource": resource,
                "severity": severity,
                "action": action,
                "status": status,
            },
        )
        return True
    except Exception as exc:  # pylint: disable=broad-except
        _logger.error(
            "Failed to write action to Firestore",
            extra={"finding_id": finding_id, "error": str(exc)},
        )
        return False
