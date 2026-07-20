"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT
"""

from typing import Any, Dict, List

from scc_processor.utils.config_loader import load_config

# SCC severity values mapped to SecureVault severity levels.
_SCC_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "SEVERITY_UNSPECIFIED": "MEDIUM",
}

# Real SCC findings use fixed findingClass enums (e.g. MISCONFIGURATION) and put
# the specific detector name in category. Map known detector categories to the
# internal finding classes used by the response matrix and remediator.
_CATEGORY_CLASS_MAP = {
    "PUBLIC_BUCKET_ACL": "PUBLIC_BUCKET_ACL",
    "OPEN_FIREWALL": "OPEN_FIREWALL",
    "OVER_PRIVILEGED_SERVICE_ACCOUNT": "OVER_PRIVILEGED_SA",
}


def classify_finding(finding: Dict[str, Any]) -> str:
    """Classify an SCC finding into a SecureVault severity level.

    Args:
        finding: The SCC finding payload as a dictionary.

    Returns:
        One of "CRITICAL", "HIGH", "MEDIUM", or "LOW".
    """
    config = load_config()
    overrides: List[str] = config.get("severity_overrides", [])

    finding_class = _extract_finding_class(finding)
    if finding_class in overrides:
        return "CRITICAL"

    scc_severity = finding.get("severity", "SEVERITY_UNSPECIFIED")
    return _SCC_SEVERITY_MAP.get(str(scc_severity).upper(), "MEDIUM")


def _extract_finding_class(finding: Dict[str, Any]) -> str:
    """Derive a normalized finding class from the SCC finding payload.

    SCC uses fixed findingClass enums such as MISCONFIGURATION, THREAT, etc.
    The actionable detector name lives in category, so category is checked
    first. If the category is unknown, fall back to findingClass, then to the
    raw category string.
    """
    category = finding.get("category", "")
    finding_class = finding.get("findingClass", "")

    category_upper = str(category).upper()
    if category_upper in _CATEGORY_CLASS_MAP:
        return _CATEGORY_CLASS_MAP[category_upper]

    # Legacy / simulated findings may set findingClass directly.
    if finding_class:
        finding_class_upper = str(finding_class).upper()
        if finding_class_upper not in {"MISCONFIGURATION", "THREAT", "VULNERABILITY", "OBSERVATION", "SCC_ERROR", "POSTURE_VIOLATION", "TOXIC_COMBINATION"}:
            return finding_class_upper

    return category_upper
