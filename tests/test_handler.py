"""Unit tests for SecureVault Cloud Function handler."""

import base64
import json
from datetime import datetime, timezone

import pytest
from cloudevents.http import CloudEvent

from main import scc_alert_handler, parse_finding, MONITORED_FINDINGS


def make_cloud_event(finding_category: str, severity: str = "CRITICAL", resource: str = "test-resource") -> CloudEvent:
    """Helper to create a CloudEvent with an SCC finding."""
    finding_data = {
        "finding": {
            "category": finding_category,
            "severity": severity,
            "resourceName": f"//storage.googleapis.com/projects/_/buckets/{resource}",
            "sourceProperties": {
                "Recommendation": "Test recommendation"
            },
            "createTime": datetime.now(timezone.utc).isoformat(),
        }
    }

    event_data = {
        "message": {
            "data": base64.b64encode(json.dumps(finding_data).encode()).decode(),
            "attributes": {"findingId": "test-123"}
        }
    }

    attributes = {
        "type": "google.cloud.pubsub.topic.v1.messagePublished",
        "source": "pubsub"
    }

    return CloudEvent(attributes, event_data)


class TestParseFinding:
    """Tests for finding parsing logic."""

    def test_public_bucket_acl_parsed(self):
        event = make_cloud_event("PUBLIC_BUCKET_ACL")
        result = parse_finding(event)
        assert result is not None
        assert result["category"] == "PUBLIC_BUCKET_ACL"
        assert result["severity"] == "CRITICAL"

    def test_open_firewall_parsed(self):
        event = make_cloud_event("OPEN_FIREWALL", severity="HIGH")
        result = parse_finding(event)
        assert result is not None
        assert result["category"] == "OPEN_FIREWALL"

    def test_over_privileged_sa_parsed(self):
        event = make_cloud_event("OVER_PRIVILEGED_SERVICE_ACCOUNT", severity="HIGH")
        result = parse_finding(event)
        assert result is not None
        assert result["category"] == "OVER_PRIVILEGED_SERVICE_ACCOUNT"

    def test_unmonitored_finding_returns_none(self):
        event = make_cloud_event("SOME_OTHER_FINDING")
        result = parse_finding(event)
        assert result is None

    def test_malformed_data_returns_none(self):
        event = CloudEvent(
            {"type": "test", "source": "test"},
            {"message": {"data": "not-valid-base64!!!"}}
        )
        result = parse_finding(event)
        assert result is None


class TestSccAlertHandler:
    """Tests for the main handler entry point."""

    def test_unmonitored_finding_skipped(self):
        event = make_cloud_event("SOME_OTHER_FINDING")
        result = scc_alert_handler(event)
        assert "not in monitored set" in result

    def test_monitored_finding_processed(self, monkeypatch):
        """Test that a monitored finding triggers email send attempt."""
        calls = []

        def mock_send(finding):
            calls.append(finding)
            return True

        monkeypatch.setattr("main.send_alert_email", mock_send)

        event = make_cloud_event("PUBLIC_BUCKET_ACL")
        result = scc_alert_handler(event)

        assert len(calls) == 1
        assert calls[0]["category"] == "PUBLIC_BUCKET_ACL"
        assert "sent" in result


class TestMonitoredFindings:
    """Tests for the MONITORED_FINDINGS configuration."""

    def test_all_findings_have_required_fields(self):
        for category, config in MONITORED_FINDINGS.items():
            assert "severity" in config
            assert "description" in config
            assert "remediation" in config

    def test_severity_values_valid(self):
        valid_severities = {"CRITICAL", "HIGH"}
        for category, config in MONITORED_FINDINGS.items():
            assert config["severity"] in valid_severities, f"{category} has invalid severity"
