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
        "name": "projects/test/sources/123/findings/notify-test",
        "findingClass": "MISCONFIGURATION",
        "category": "OPEN_FIREWALL",
        "severity": "CRITICAL",
        "resourceName": "//compute.googleapis.com/projects/test/global/firewalls/allow-all-ssh",
        "createTime": "2026-07-03T12:00:00Z",
    }


@patch("scc_processor.processors.notifier.requests")
def test_email_payload_format(mock_requests, base_finding, env_vars):
    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    action_result = {"action": "OPEN_FIREWALL", "status": "SUCCESS"}
    assert send_alert(base_finding, action_result) is True

    call_args = mock_requests.post.call_args
    payload = call_args.kwargs["json"]
    assert "[SecureVault] CRITICAL: OPEN_FIREWALL" in payload["subject"]
    assert payload["to"][0]["email"] == "alerts@example.com"
    assert "OPEN_FIREWALL" in payload["textContent"]
    assert "SUCCESS" in payload["textContent"]


@patch("scc_processor.processors.notifier.requests")
def test_brevo_failure_returns_false(mock_requests, base_finding, env_vars):
    mock_requests.RequestException = real_requests.exceptions.RequestException
    mock_requests.post.side_effect = real_requests.exceptions.RequestException("Brevo timeout")

    action_result = {"action": "OPEN_FIREWALL", "status": "SUCCESS"}
    assert send_alert(base_finding, action_result) is False


@patch("scc_processor.processors.notifier.requests")
def test_api_key_read_from_environment(mock_requests, base_finding, env_vars):
    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"})

    headers = mock_requests.post.call_args.kwargs["headers"]
    assert headers["api-key"] == "fake-brevo-api-key"


@patch("scc_processor.processors.notifier.requests")
def test_missing_alert_email_returns_false(mock_requests, base_finding, monkeypatch):
    monkeypatch.delenv("ALERT_EMAIL", raising=False)
    assert send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"}) is False
    mock_requests.post.assert_not_called()


@patch("scc_processor.processors.notifier.requests")
def test_missing_brevo_key_returns_false(mock_requests, base_finding, monkeypatch):
    monkeypatch.delenv("BREVO_API_KEY", raising=False)
    assert send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"}) is False
    mock_requests.post.assert_not_called()


@patch("scc_processor.processors.notifier.requests")
def test_surrounding_whitespace_is_stripped_from_the_api_key(
    mock_requests, base_finding, env_vars, monkeypatch
):
    """A secret version added with `echo` keeps its trailing newline. Brevo
    answers the malformed header with a 401 that looks exactly like a revoked
    key, so the value is stripped rather than trusted verbatim."""
    monkeypatch.setenv("BREVO_API_KEY", "  fake-brevo-api-key\n")
    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"})

    assert mock_requests.post.call_args.kwargs["headers"]["api-key"] == "fake-brevo-api-key"


@patch("scc_processor.processors.notifier.requests")
def test_a_whitespace_only_api_key_is_treated_as_missing(mock_requests, base_finding, env_vars, monkeypatch):
    monkeypatch.setenv("BREVO_API_KEY", "   \n")
    assert send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"}) is False
    mock_requests.post.assert_not_called()


@patch("scc_processor.processors.notifier.requests")
def test_an_smtp_relay_key_is_rejected_before_the_request(
    mock_requests, base_finding, env_vars, monkeypatch
):
    """Brevo's SMTP relay keys authenticate against smtp-relay.brevo.com, not
    the v3 REST API, which answers them with a bare 401. Catching the prefix
    turns an opaque auth failure into an actionable one."""
    monkeypatch.setenv("BREVO_API_KEY", "xsmtpsib-not-a-rest-api-key")
    assert send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"}) is False
    mock_requests.post.assert_not_called()


@patch("scc_processor.processors.notifier.requests")
def test_a_v3_api_key_is_accepted(mock_requests, base_finding, env_vars, monkeypatch):
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-a-real-looking-rest-api-key")
    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    assert send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"}) is True


@patch("scc_processor.processors.notifier.requests")
def test_subject_contains_severity_and_finding_class(mock_requests, base_finding, env_vars):
    response = MagicMock()
    response.status_code = 201
    response.raise_for_status.return_value = None
    mock_requests.post.return_value = response

    send_alert(base_finding, {"action": "ALERT", "status": "SUCCESS"})

    payload = mock_requests.post.call_args.kwargs["json"]
    assert "CRITICAL" in payload["subject"]
    assert "OPEN_FIREWALL" in payload["subject"]
