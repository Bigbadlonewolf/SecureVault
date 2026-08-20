"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from typing import Optional

from google.cloud import firestore

from scc_processor.utils.logger import get_logger

_logger = get_logger()

# Firestore caps a document ID at 1500 bytes.
_MAX_DOCUMENT_ID_BYTES = 1500


def _document_id(finding_id: str) -> str:
    """Convert an SCC finding name into a valid Firestore document ID.

    SCC finding names are resource paths (``projects/p/sources/s/findings/f``).
    Firestore reads a forward slash as a collection separator, so passing one
    through yields a reference with an odd number of path elements and raises
    ``ValueError: A document must have an even number of path elements`` before
    any write is attempted. Slashes are the only character Firestore forbids in
    an ID; the colons and plus signs in the timestamp segment are legal.

    Args:
        finding_id: The SCC finding name, or any caller-supplied identifier.

    Returns:
        A document ID safe to pass to ``CollectionReference.document()``.
    """
    doc_id = (finding_id or "unknown").replace("/", "_")
    # Firestore reserves "." , ".." and the __name__ pattern.
    if doc_id in (".", "..") or (doc_id.startswith("__") and doc_id.endswith("__")):
        doc_id = f"id_{doc_id}"
    encoded = doc_id.encode("utf-8")
    if len(encoded) > _MAX_DOCUMENT_ID_BYTES:
        doc_id = encoded[:_MAX_DOCUMENT_ID_BYTES].decode("utf-8", "ignore")
    return doc_id


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
        finding_id: Unique SCC finding identifier. Slash-escaped by
            ``_document_id`` for use as the document ID, and stored verbatim in
            the document body.
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
        doc_ref = client.collection("remediation_log").document(_document_id(finding_id))
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
