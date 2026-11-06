# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        src.lh_ssl_tracker.exporters.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Exporters package for lh-ssl-tracker.

Provides table, JSON, and SARIF output formats.
"""

from __future__ import annotations

from enum import StrEnum

from lh_ssl_tracker.exporters.json_exporter import export_json
from lh_ssl_tracker.exporters.sarif import export_sarif
from lh_ssl_tracker.exporters.table import render_table_report


class OutputFormat(StrEnum):
    """Supported output formats for reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


__all__ = [
    "OutputFormat",
    "export_json",
    "export_sarif",
    "render_table_report",
]
