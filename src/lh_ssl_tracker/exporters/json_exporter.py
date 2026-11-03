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
