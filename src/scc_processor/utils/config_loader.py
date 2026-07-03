"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

import os
from typing import Any, Dict

import yaml

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml")
_config_cache: Dict[str, Any] = {}


def load_config(path: str = _CONFIG_PATH) -> Dict[str, Any]:
    """Load and cache the non-sensitive YAML configuration.

    The configuration is loaded once per cold start and cached in a module-level
    dictionary to avoid repeated disk I/O.
    """
    global _config_cache  # pylint: disable=global-statement
    if _config_cache:
        return _config_cache

    resolved = os.path.abspath(path)
    with open(resolved, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    if not isinstance(config, dict):
        raise ValueError(f"Configuration file {resolved} did not parse to a mapping")

    _validate_config(config)
    _config_cache = config
    return _config_cache


def _validate_config(config: Dict[str, Any]) -> None:
    """Ensure required configuration keys are present."""
    matrix = config.get("response_matrix")
    if not isinstance(matrix, dict):
        raise ValueError("Missing or invalid 'response_matrix' in config.yaml")

    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        if severity not in matrix:
            raise ValueError(f"Missing severity level '{severity}' in response_matrix")

    critical = matrix["CRITICAL"]
    if not isinstance(critical.get("auto_remediate"), list):
        raise ValueError("Missing or invalid 'CRITICAL.auto_remediate' list")
    if "default_action" not in critical:
        raise ValueError("Missing 'CRITICAL.default_action'")

    if matrix["HIGH"].get("action") is None:
        raise ValueError("Missing 'HIGH.action'")
    if matrix["MEDIUM"].get("action") is None:
        raise ValueError("Missing 'MEDIUM.action'")


def clear_cache() -> None:
    """Clear the cached configuration; useful in tests."""
    global _config_cache  # pylint: disable=global-statement
    _config_cache = {}
