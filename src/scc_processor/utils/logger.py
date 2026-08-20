"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

_logger: Optional[logging.Logger] = None

# Attributes every LogRecord carries. Anything on the record outside this set
# was supplied by the caller via ``extra=`` and belongs in the JSON payload.
_STANDARD_RECORD_KEYS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def get_logger(name: str = "securevault") -> logging.Logger:
    """Return a structured JSON logger compatible with Cloud Logging.

    A single stdout handler is used in every environment, including on GCP.
    Cloud Functions and Cloud Run parse single-line JSON written to stdout into
    ``jsonPayload``, so the ``google-cloud-logging`` client buys nothing here —
    and ``Client.setup_logging()`` actively costs something, because its handler
    drops the ``extra=`` fields that every call site in this package relies on.
    Under it, ``_JsonFormatter`` was never attached in production and every
    correlation ID, finding ID, and error string was discarded before leaving
    the process.
    """
    global _logger  # pylint: disable=global-statement
    if _logger is not None:
        return _logger

    level = _LOG_LEVELS.get(os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)

    # The functions framework installs its own root handler. Without this every
    # record is emitted twice: once as JSON, once as an unstructured duplicate.
    logger.propagate = False

    _logger = logger
    return logger


def reset_logger() -> None:
    """Drop the cached logger so the next ``get_logger()`` call rebuilds it."""
    global _logger  # pylint: disable=global-statement
    _logger = None


class _JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON for Cloud Logging ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Merge any extra fields passed by the caller via logger(..., extra={...}).
        for key, value in record.__dict__.items():
            if key not in payload and key not in _STANDARD_RECORD_KEYS:
                payload[key] = value
        return json.dumps(payload, default=str)
