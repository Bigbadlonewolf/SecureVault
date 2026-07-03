"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import base64
import json

import pytest

from main import _parse_finding


def test_parse_finding_unwraps_scc_notification():
    finding = {"findingId": "wrapped", "severity": "HIGH"}
    event = {"data": base64.b64encode(json.dumps({"finding": finding}).encode()).decode()}
    assert _parse_finding(event) == finding


def test_parse_finding_accepts_direct_payload():
    finding = {"findingId": "direct", "severity": "MEDIUM"}
    event = {"data": base64.b64encode(json.dumps(finding).encode()).decode()}
    assert _parse_finding(event) == finding


def test_parse_finding_missing_data_raises():
    with pytest.raises(ValueError, match="missing 'data' field"):
        _parse_finding({})
