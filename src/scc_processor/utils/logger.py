"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional

import google.cloud.logging

_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

_logger: Optional[logging.Logger] = None


def get_logger(name: str = "securevault") -> logging.Logger:
    """Return a structured JSON logger compatible with Cloud Logging."""
    global _logger  # pylint: disable=global-statement
    if _logger is not None:
        return _logger

    level = _LOG_LEVELS.get(os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []

    # Attach a Cloud Logging handler when running on GCP; otherwise use a JSON stream handler
    # so local development still emits structured logs.
    if os.environ.get("K_SERVICE"):
        try:
            client = google.cloud.logging.Client()
            client.setup_logging(log_level=level)
            _logger = logger
            return logger
        except Exception as exc:  # pragma: no cover - graceful fallback
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "Cloud Logging client unavailable; falling back to stdout: %s", exc
            )

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)

    _logger = logger
    return logger


class _JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON for Cloud Logging ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": self.formatTime(record),
        }
        if hasattr(record, "correlation_id") and record.correlation_id:
            payload["correlation_id"] = record.correlation_id
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Merge any extra fields added via logger.extra
        for key, value in record.__dict__.items():
            if key not in payload and key not in (
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
            ):
                payload[key] = value
        return json.dumps(payload, default=str)
