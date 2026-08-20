"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import json
import logging

import pytest

from scc_processor.utils import logger as logger_module
from scc_processor.utils.logger import get_logger, reset_logger


@pytest.fixture(autouse=True)
def fresh_logger():
    """Rebuild the cached module logger around every test."""
    reset_logger()
    yield
    reset_logger()


def _emit(capsys, level: str = "info", **kwargs) -> dict:
    """Log one record and return its parsed JSON payload."""
    log = get_logger("securevault-test")
    getattr(log, level)("test message", **kwargs)
    for handler in log.handlers:
        handler.flush()
    out = capsys.readouterr().out.strip().splitlines()
    assert out, "logger wrote nothing to stdout"
    return json.loads(out[-1])


def test_extra_fields_reach_the_payload(capsys):
    payload = _emit(
        capsys,
        extra={"correlation_id": "abc-123", "finding_id": "f-1", "error": "boom"},
    )
    assert payload["correlation_id"] == "abc-123"
    assert payload["finding_id"] == "f-1"
    assert payload["error"] == "boom"


def test_extra_fields_survive_on_cloud_functions(monkeypatch, capsys):
    """Regression: under google-cloud-logging's handler, K_SERVICE caused
    get_logger to return before _JsonFormatter was attached, so every extra
    field was silently dropped in production while passing locally."""
    monkeypatch.setenv("K_SERVICE", "scc-processor")
    payload = _emit(capsys, level="error", extra={"error": "handler exploded"})
    assert payload["error"] == "handler exploded"
    assert payload["severity"] == "ERROR"


def test_payload_carries_severity_message_and_utc_timestamp(capsys):
    payload = _emit(capsys, level="warning")
    assert payload["severity"] == "WARNING"
    assert payload["message"] == "test message"
    assert payload["logger"] == "securevault-test"
    assert payload["timestamp"].endswith("+00:00")


def test_exception_text_is_serialized(capsys):
    log = get_logger("securevault-test")
    try:
        raise ValueError("A document must have an even number of path elements")
    except ValueError:
        log.exception("write failed")
    for handler in log.handlers:
        handler.flush()
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert "ValueError" in payload["exception"]
    assert "even number of path elements" in payload["exception"]


def test_standard_record_attributes_are_not_leaked(capsys):
    payload = _emit(capsys)
    for key in ("msg", "args", "pathname", "levelno", "created", "thread"):
        assert key not in payload


def test_records_do_not_propagate_to_the_root_handler():
    log = get_logger("securevault-test")
    assert log.propagate is False


def test_log_level_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "ERROR")
    assert get_logger("securevault-test").level == logging.ERROR


def test_unknown_log_level_falls_back_to_info(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "LOUD")
    assert get_logger("securevault-test").level == logging.INFO


def test_logger_is_cached_across_calls():
    assert get_logger("securevault-test") is get_logger("securevault-test")


def test_the_cloud_logging_client_is_not_imported():
    """The dependency is removed from requirements.txt; importing it here would
    fail at cold start in production, where it is no longer installed."""
    assert not hasattr(logger_module, "google")
