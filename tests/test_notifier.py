"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from unittest.mock import MagicMock, patch

import pytest
import requests as real_requests

from scc_processor.processors.notifier import send_alert


@pytest.fixture
def base_finding():
    return {
        "findingId": "notify-test",
        "findingClass": "OPEN_FIREWALL",
        "severity": "CRITICAL",
        "resource": "projects/test/firewalls/allow-all-ssh",
        "createTime": "2026-07-03T12:00:00Z",
    }


@patch("scc_processor.processors.notifier.secretmanager")
@patch("scc_processor.processors.notifier.requests")
def test_email_payload_format(mock_requests, mock_secretmanager, base_finding, env_vars):
    secret_client = MagicMock()
    secret_client.access_secret_version.return_value.payload.data = b"fake-api-key"
    mock_secretmanager.SecretManagerServiceClient.return_value = secret_client

    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    action_result = {"action": "OPEN_FIREWALL", "status": "SUCCESS"}
    assert send_alert(base_finding, action_result) is True

    call_args = mock_requests.post.call_args
    payload = call_args.kwargs["json"]
    assert "[SecureVault] CRITICAL: OPEN_FIREWALL" in payload["subject"]
    assert payload["to"][0]["email"] == "Lanreoluokunigbadwolf@gmail.com"
    assert "OPEN_FIREWALL" in payload["textContent"]
    assert "SUCCESS" in payload["textContent"]


@patch("scc_processor.processors.notifier.secretmanager")
@patch("scc_processor.processors.notifier.requests")
def test_brevo_failure_returns_false(mock_requests, mock_secretmanager, base_finding, env_vars):
    secret_client = MagicMock()
    secret_client.access_secret_version.return_value.payload.data = b"fake-api-key"
    mock_secretmanager.SecretManagerServiceClient.return_value = secret_client

    mock_requests.RequestException = real_requests.exceptions.RequestException
    mock_requests.post.side_effect = real_requests.exceptions.RequestException("Brevo timeout")

    action_result = {"action": "OPEN_FIREWALL", "status": "SUCCESS"}
    assert send_alert(base_finding, action_result) is False


@patch("scc_processor.processors.notifier.secretmanager")
@patch("scc_processor.processors.notifier.requests")
def test_secret_manager_key_retrieval(mock_requests, mock_secretmanager, base_finding, env_vars):
    secret_client = MagicMock()
    secret_client.access_secret_version.return_value.payload.data = b"retrieved-key"
    mock_secretmanager.SecretManagerServiceClient.return_value = secret_client

    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"})

    headers = mock_requests.post.call_args.kwargs["headers"]
    assert headers["api-key"] == "retrieved-key"


@patch("scc_processor.processors.notifier.secretmanager")
@patch("scc_processor.processors.notifier.requests")
def test_missing_alert_email_returns_false(mock_requests, mock_secretmanager, base_finding, monkeypatch):
    monkeypatch.delenv("ALERT_EMAIL", raising=False)
    assert send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"}) is False
    mock_requests.post.assert_not_called()


@patch("scc_processor.processors.notifier.secretmanager")
@patch("scc_processor.processors.notifier.requests")
def test_subject_contains_severity_and_finding_class(mock_requests, mock_secretmanager, base_finding, env_vars):
    secret_client = MagicMock()
    secret_client.access_secret_version.return_value.payload.data = b"fake-api-key"
    mock_secretmanager.SecretManagerServiceClient.return_value = secret_client

    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"})

    payload = mock_requests.post.call_args.kwargs["json"]
    assert "CRITICAL" in payload["subject"]
    assert "OPEN_FIREWALL" in payload["subject"]
