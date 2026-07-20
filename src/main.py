"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT

Cloud Functions entry point. functions-framework loads ./main.py from the
source root and resolves the configured entry point as a module-level
attribute (no dotted-path traversal), so the handler is re-exported here
from the scc_processor package.
"""

from scc_processor.main import process_scc_finding

__all__ = ["process_scc_finding"]
