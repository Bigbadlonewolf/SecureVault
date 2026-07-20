"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import base64
import json
from unittest.mock import patch

from cloudevents.http import CloudEvent

from scc_processor.main import process_scc_finding

_PROJECT = "mythical-cider-496423-h6"


def _pubsub_cloudevent(payload: dict) -> CloudEvent:
    """Build the CloudEvent Eventarc delivers for a Pub/Sub message."""
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return CloudEvent(
        {
            "specversion": "1.0",
            "id": "test-event-id",
            "source": f"//pubsub.googleapis.com/projects/{_PROJECT}/topics/scc-findings",
            "type": "google.cloud.pubsub.topic.v1.messagePublished",
            "time": "2026-07-03T12:00:00Z",
        },
        {
            "message": {
                "data": encoded,
                "messageId": "test-message-id",
                "publishTime": "2026-07-03T12:00:00Z",
            },
            "subscription": f"projects/{_PROJECT}/subscriptions/eventarc-scc-findings",
        },
    )


@patch("scc_processor.main.stream_finding")
@patch("scc_processor.main.log_action")
@patch("scc_processor.main.send_alert")
@patch("scc_processor.main.remediate")
def test_critical_finding_triggers_remediation_and_alert(
    mock_remediate, mock_alert, mock_log_action, mock_stream, env_vars
):
    mock_remediate.return_value = {"action": "PUBLIC_BUCKET_ACL", "status": "SUCCESS"}
    mock_alert.return_value = True

    finding = {
        "finding": {
            "name": f"projects/{_PROJECT}/sources/123/findings/f4-public-bucket",
            "parent": f"projects/{_PROJECT}/sources/123",
            "resourceName": "//storage.googleapis.com/public-test-bucket",
            "state": "ACTIVE",
            "category": "PUBLIC_BUCKET_ACL",
            "severity": "HIGH",
            "findingClass": "MISCONFIGURATION",
            "eventTime": "2026-07-03T12:03:00Z",
            "createTime": "2026-07-03T12:03:00Z",
        }
    }

    result = process_scc_finding(_pubsub_cloudevent(finding))
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
    mock_remediate, mock_alert, mock_log_action, mock_stream, env_vars
):
    mock_alert.return_value = True

    finding = {
        "finding": {
            "name": f"projects/{_PROJECT}/sources/123/findings/f2-high",
            "parent": f"projects/{_PROJECT}/sources/123",
            "resourceName": f"//bigquery.googleapis.com/projects/{_PROJECT}/datasets/sensitive",
            "state": "ACTIVE",
            "category": "PUBLIC_DATASET",
            "severity": "HIGH",
            "findingClass": "MISCONFIGURATION",
            "eventTime": "2026-07-03T12:01:00Z",
            "createTime": "2026-07-03T12:01:00Z",
        }
    }

    result = process_scc_finding(_pubsub_cloudevent(finding))
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
    mock_remediate, mock_alert, mock_log_action, mock_stream, env_vars
):
    finding = {
        "finding": {
            "name": f"projects/{_PROJECT}/sources/123/findings/f3-medium",
            "parent": f"projects/{_PROJECT}/sources/123",
            "resourceName": f"//iam.googleapis.com/projects/{_PROJECT}/serviceAccounts/unused@{_PROJECT}.iam.gserviceaccount.com",
            "state": "ACTIVE",
            "category": "SERVICE_ACCOUNT_KEY_NOT_ROTATED",
            "severity": "MEDIUM",
            "findingClass": "MISCONFIGURATION",
            "eventTime": "2026-07-03T12:02:00Z",
            "createTime": "2026-07-03T12:02:00Z",
        }
    }

    result = process_scc_finding(_pubsub_cloudevent(finding))
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
    mock_remediate, mock_alert, mock_log_action, mock_stream, env_vars
):
    mock_remediate.return_value = {"action": "OPEN_FIREWALL", "status": "SUCCESS"}
    mock_alert.return_value = True

    finding_name = f"projects/{_PROJECT}/sources/123/findings/f1-critical"
    finding = {
        "finding": {
            "name": finding_name,
            "parent": f"projects/{_PROJECT}/sources/123",
            "resourceName": f"//compute.googleapis.com/projects/{_PROJECT}/global/firewalls/allow-all-ssh",
            "state": "ACTIVE",
            "category": "OPEN_FIREWALL",
            "severity": "CRITICAL",
            "findingClass": "MISCONFIGURATION",
            "eventTime": "2026-07-03T12:00:00Z",
            "createTime": "2026-07-03T12:00:00Z",
        }
    }

    process_scc_finding(_pubsub_cloudevent(finding))

    call_kwargs = mock_stream.call_args.kwargs
    assert call_kwargs["finding_id"] == finding_name
    assert call_kwargs["resource_type"] == "compute.googleapis.com/Firewall"
    assert call_kwargs["severity"] == "CRITICAL"
    assert call_kwargs["finding_class"] == "OPEN_FIREWALL"
    assert call_kwargs["action"] == "OPEN_FIREWALL"
    assert call_kwargs["project_id"] == _PROJECT
    assert call_kwargs["status"] == "SUCCESS"


@patch("scc_processor.main.stream_finding")
@patch("scc_processor.main.log_action")
@patch("scc_processor.main.send_alert")
@patch("scc_processor.main.remediate")
def test_over_privileged_sa_is_alert_only_not_remediated(
    mock_remediate, mock_alert, mock_log_action, mock_stream, env_vars
):
    mock_alert.return_value = True

    finding = {
        "finding": {
            "name": f"projects/{_PROJECT}/sources/123/findings/f5-overpriv-sa",
            "parent": f"projects/{_PROJECT}/sources/123",
            "resourceName": f"//iam.googleapis.com/projects/{_PROJECT}/serviceAccounts/overpriv@{_PROJECT}.iam.gserviceaccount.com",
            "state": "ACTIVE",
            "category": "OVER_PRIVILEGED_SERVICE_ACCOUNT",
            "severity": "HIGH",
            "findingClass": "MISCONFIGURATION",
            "eventTime": "2026-07-03T12:04:00Z",
            "createTime": "2026-07-03T12:04:00Z",
        }
    }

    result = process_scc_finding(_pubsub_cloudevent(finding))
    assert result == "OK"
    mock_remediate.assert_not_called()
    mock_alert.assert_called_once()
    mock_log_action.assert_called_once()
    mock_stream.assert_called_once()
