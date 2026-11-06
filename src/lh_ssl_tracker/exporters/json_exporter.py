# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        src.lh_ssl_tracker.exporters.json_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Structured JSON exporter for audit reports.

Serializes audit reports, security findings, certificate metrics,
and CT log monitoring results into JSON.
"""

from __future__ import annotations

import json

from lh_ssl_tracker.models import AuditReport


def export_json(report: AuditReport, indent: int = 2) -> str:
    """Serialize an AuditReport to a formatted JSON string.

    Args:
        report: AuditReport instance to export.
        indent: Indentation spaces (defaults to 2).

    Returns:
        JSON string representation.
    """
    report_dict = report.to_dict()
    return json.dumps(report_dict, indent=indent, default=str)
