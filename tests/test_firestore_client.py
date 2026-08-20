"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from unittest.mock import MagicMock, patch

import pytest

from scc_processor.storage.firestore_client import _document_id, log_action

# A real SCC finding name: a resource path, not a bare identifier.
SCC_FINDING_NAME = (
    "projects/securevault-demo/sources/123/findings/"
    "sim-PUBLIC_BUCKET_ACL-2026-08-19T22:33:07.036141+00:00"
)


def test_slashes_are_escaped():
    """Regression: the raw finding name gave the reference 7 path elements, so
    Firestore raised 'A document must have an even number of path elements' on
    every single invocation."""
    doc_id = _document_id(SCC_FINDING_NAME)
    assert "/" not in doc_id
    assert doc_id.startswith("projects_securevault-demo_sources_123_findings_")


def test_timestamp_characters_are_preserved():
    """Colons and plus signs are legal in a Firestore document ID."""
    assert "2026-08-19T22:33:07.036141+00:00" in _document_id(SCC_FINDING_NAME)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", "unknown"),
        (".", "id_."),
        ("..", "id_.."),
        ("__name__", "id___name__"),
        ("plain-id", "plain-id"),
    ],
)
def test_reserved_and_empty_ids_are_rewritten(raw, expected):
    assert _document_id(raw) == expected


def test_oversized_ids_are_truncated_to_the_firestore_limit():
    assert len(_document_id("x" * 4000).encode("utf-8")) == 1500


@patch("scc_processor.storage.firestore_client.firestore")
def test_log_action_writes_a_valid_reference(mock_firestore, env_vars):
    client = MagicMock()
    mock_firestore.Client.return_value = client

    assert log_action(
        finding_id=SCC_FINDING_NAME,
        resource="//storage.googleapis.com/public-bucket",
        severity="CRITICAL",
        action="PUBLIC_BUCKET_ACL",
        status="SUCCESS",
    ) is True

    document_id = client.collection.return_value.document.call_args.args[0]
    assert "/" not in document_id
    client.collection.assert_called_once_with("remediation_log")


@patch("scc_processor.storage.firestore_client.firestore")
def test_the_document_body_keeps_the_original_finding_name(mock_firestore, env_vars):
    client = MagicMock()
    mock_firestore.Client.return_value = client

    log_action(
        finding_id=SCC_FINDING_NAME,
        resource="//storage.googleapis.com/public-bucket",
        severity="CRITICAL",
        action="PUBLIC_BUCKET_ACL",
        status="SUCCESS",
    )

    payload = client.collection.return_value.document.return_value.set.call_args.args[0]
    assert payload["finding_id"] == SCC_FINDING_NAME


@patch("scc_processor.storage.firestore_client.firestore")
def test_write_failure_returns_false(mock_firestore, env_vars):
    client = MagicMock()
    client.collection.return_value.document.return_value.set.side_effect = RuntimeError(
        "permission denied"
    )
    mock_firestore.Client.return_value = client

    assert log_action(
        finding_id=SCC_FINDING_NAME,
        resource="//storage.googleapis.com/public-bucket",
        severity="CRITICAL",
        action="PUBLIC_BUCKET_ACL",
        status="FAILURE",
        error="permission denied",
    ) is False
