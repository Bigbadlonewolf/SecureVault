"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure src/ is on the Python path for imports.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from utils.config_loader import clear_cache  # noqa: E402


@pytest.fixture(autouse=True)
def reset_config_cache():
    """Clear the configuration cache before each test."""
    clear_cache()
    yield


@pytest.fixture
def env_vars(monkeypatch):
    """Set required environment variables for tests."""
    monkeypatch.setenv("PROJECT_ID", "mythical-cider-496423-h6")
    monkeypatch.setenv("ALERT_EMAIL", "Lanreoluokunigbadwolf@gmail.com")
    monkeypatch.setenv("BREVO_SECRET_ID", "brevo-api-key")
    monkeypatch.setenv("BIGQUERY_DATASET", "securevault_analytics")
    monkeypatch.setenv("BIGQUERY_TABLE", "findings_history")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")


@pytest.fixture
def load_fixture():
    """Load a test fixture by filename."""

    def _load(name: str):
        path = PROJECT_ROOT / "tests" / "fixtures" / name
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    return _load
