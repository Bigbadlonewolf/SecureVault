"""
SecureVault: GCP Security Detection & Response Pipeline
Architect: Lanre Oluokun | Implementation: AI-assisted
License: MIT

Cloud Functions entry point. functions-framework loads ./main.py from the
source root and resolves the configured entry point as a module-level
attribute (no dotted-path traversal), so the handler is re-exported here
from the scc_processor package.

The @cloud_event registration is required, not cosmetic. Without it the
framework falls back to the legacy background-function signature and calls
the handler as (data, context), which raises

    TypeError: process_scc_finding() takes 1 positional argument but 2 were given

on every delivery. Registering here rather than in scc_processor.main keeps
the package importable without functions-framework, so the unit tests can go
on calling the handler directly.
"""

import functions_framework

from scc_processor.main import process_scc_finding as _process_scc_finding

process_scc_finding = functions_framework.cloud_event(_process_scc_finding)

__all__ = ["process_scc_finding"]
