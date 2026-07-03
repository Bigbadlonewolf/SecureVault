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
    """Derive a normalized finding class from the SCC finding payload."""
    category = finding.get("category", "")
    finding_class = finding.get("findingClass", "")
    if finding_class:
        return str(finding_class).upper()

    # Map common SCC categories to internal finding classes.
    category_upper = str(category).upper()
    if "BUCKET" in category_upper or "STORAGE" in category_upper:
        return "PUBLIC_BUCKET_ACL"
    if "FIREWALL" in category_upper:
        return "OPEN_FIREWALL"
    if "PRIVILEGE" in category_upper or "IAM" in category_upper:
        return "OVER_PRIVILEGED_SA"
    return category_upper
