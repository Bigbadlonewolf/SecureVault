"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from scc_processor.main import process_scc_finding


def _pubsub_event(payload: dict) -> dict:
    return {"data": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")}


@pytest.fixture
def context():
    ctx = MagicMock()
    ctx.event_id = "test-event-id"
    return ctx


@patch("scc_processor.main.stream_finding")
@patch("scc_processor.main.log_action")
@patch("scc_processor.main.send_alert")
@patch("scc_processor.main.remediate")
def test_critical_finding_triggers_remediation_and_alert(
    mock_remediate, mock_alert, mock_log_action, mock_stream, context, env_vars
):
    mock_remediate.return_value = {"action": "PUBLIC_BUCKET_ACL", "status": "SUCCESS"}
    mock_alert.return_value = True

    finding = {
        "finding": {
            "findingId": "f4-public-bucket",
            "findingClass": "PUBLIC_BUCKET_ACL",
            "category": "STORAGE_BUCKET_PUBLIC",
            "severity": "HIGH",
            "resource": "gs://public-test-bucket",
            "resourceType": "storage.googleapis.com/Bucket",
            "projectId": "mythical-cider-496423-h6",
            "createTime": "2026-07-03T12:03:00Z",
        }
    }

    result = process_scc_finding(_pubsub_event(finding), context)
    assert result == "OK"
    mock_remediate.assert_called_once()
    mock_alert.assert_called_once()
    mock_log_action.assert_called_once()
    mock_stream.assert_called_once()


@patch("scc_processor.main.stream_finding")
@patch("scc_processor.main.log_action")
@patch("scc_processor.main.send_alert")
@patch("scc_processor.main.remediate")
def test_high_finding_triggers_alert_only(
    mock_remediate, mock_alert, mock_log_action, mock_stream, context, env_vars
):
    mock_alert.return_value = True

    finding = {
        "finding": {
            "findingId": "f2-high",
            "findingClass": "DLP",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "resource": "projects/mythical-cider-496423-h6/bigQueryDatasets/sensitive",
            "resourceType": "bigquery.googleapis.com/Dataset",
            "projectId": "mythical-cider-496423-h6",
            "createTime": "2026-07-03T12:01:00Z",
        }
    }

    result = process_scc_finding(_pubsub_event(finding), context)
    assert result == "OK"
    mock_remediate.assert_not_called()
    mock_alert.assert_called_once()
    mock_log_action.assert_called_once()
    mock_stream.assert_called_once()


@patch("scc_processor.main.stream_finding")
@patch("scc_processor.main.log_action")
@patch("scc_processor.main.send_alert")
@patch("scc_processor.main.remediate")
def test_medium_finding_logged_not_alerted(
    mock_remediate, mock_alert, mock_log_action, mock_stream, context, env_vars
):
    finding = {
        "finding": {
            "findingId": "f3-medium",
            "findingClass": "UNUSED_SERVICE_ACCOUNT",
            "category": "SERVICE_ACCOUNT",
            "severity": "MEDIUM",
            "resource": "projects/mythical-cider-496423-h6/serviceAccounts/unused@mythical-cider-496423-h6.iam.gserviceaccount.com",
            "resourceType": "iam.googleapis.com/ServiceAccount",
            "projectId": "mythical-cider-496423-h6",
            "createTime": "2026-07-03T12:02:00Z",
        }
    }

    result = process_scc_finding(_pubsub_event(finding), context)
    assert result == "OK"
    mock_remediate.assert_not_called()
    mock_alert.assert_not_called()
    mock_log_action.assert_called_once()
    mock_stream.assert_called_once()


@patch("scc_processor.main.stream_finding")
@patch("scc_processor.main.log_action")
@patch("scc_processor.main.send_alert")
@patch("scc_processor.main.remediate")
def test_bigquery_streaming_called_with_correct_parameters(
    mock_remediate, mock_alert, mock_log_action, mock_stream, context, env_vars
):
    mock_remediate.return_value = {"action": "OPEN_FIREWALL", "status": "SUCCESS"}
    mock_alert.return_value = True

    finding = {
        "finding": {
            "findingId": "f1-critical",
            "findingClass": "OPEN_FIREWALL",
            "category": "FIREWALL_OPEN",
            "severity": "CRITICAL",
            "resource": "projects/mythical-cider-496423-h6/firewalls/allow-all-ssh",
            "resourceType": "compute.googleapis.com/Firewall",
            "projectId": "mythical-cider-496423-h6",
            "createTime": "2026-07-03T12:00:00Z",
        }
    }

    process_scc_finding(_pubsub_event(finding), context)

    call_kwargs = mock_stream.call_args.kwargs
    assert call_kwargs["finding_id"] == "f1-critical"
    assert call_kwargs["resource_type"] == "compute.googleapis.com/Firewall"
    assert call_kwargs["severity"] == "CRITICAL"
    assert call_kwargs["finding_class"] == "OPEN_FIREWALL"
    assert call_kwargs["action"] == "OPEN_FIREWALL"
    assert call_kwargs["project_id"] == "mythical-cider-496423-h6"
    assert call_kwargs["status"] == "SUCCESS"
