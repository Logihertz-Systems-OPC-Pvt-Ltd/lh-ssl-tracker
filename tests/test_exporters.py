# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Table, JSON, SARIF)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from lh_ssl_tracker.analyzer import CertificateAnalyzer
from lh_ssl_tracker.certificate import parse_pem_bundle
from lh_ssl_tracker.ct_monitor import CTAuditResult
from lh_ssl_tracker.exporters import export_json, export_sarif, render_table_report
from lh_ssl_tracker.models import AuditReport, Finding, FindingCategory, FindingSeverity


def test_table_report_rendering(valid_cert_pem: str) -> None:
    """Test Rich table report rendering to text string."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    analyzer = CertificateAnalyzer(warn_days=30, crit_days=7)
    audit_res = analyzer.analyze(cert, target="app.example.com")

    report = AuditReport(
        report_type="endpoint_check",
        generated_at=datetime.now(UTC),
        parameters={"warn_days": 30, "crit_days": 7},
        results=[audit_res],
    )

    rendered = render_table_report(report)
    assert "lh-ssl-tracker: Endpoint Check" in rendered
    assert "app.example.com" in rendered
    assert "Targets Audited:" in rendered


def test_json_report_export(valid_cert_pem: str) -> None:
    """Test structured JSON report export structure."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    analyzer = CertificateAnalyzer()
    audit_res = analyzer.analyze(cert, target="app.example.com")

    report = AuditReport(
        report_type="endpoint_check",
        generated_at=datetime.now(UTC),
        parameters={"test": True},
        results=[audit_res],
    )

    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "endpoint_check"
    assert "summary" in data
    assert data["summary"]["total_targets"] == 1
    assert len(data["results"]) == 1
    assert data["results"][0]["target"] == "app.example.com"


def test_sarif_v210_export(valid_cert_pem: str) -> None:
    """Test OASIS SARIF v2.1.0 export schema compliance."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    analyzer = CertificateAnalyzer(warn_days=365)  # Force a warning
    audit_res = analyzer.analyze(cert, target="app.example.com")

    # Add a CT result with rogue finding
    ct_finding = Finding(
        rule_id="CT-ROGUE-001",
        title="Rogue Subdomain Detected",
        category=FindingCategory.ROGUE_SUBDOMAIN,
        severity=FindingSeverity.HIGH,
        target="shadow.example.com",
        message="Shadow subdomain detected in CT logs",
    )
    ct_result = CTAuditResult(
        domain="example.com",
        total_entries=1,
        allowed_subdomains_count=1,
        rogue_subdomains=["shadow.example.com"],
        findings=[ct_finding],
    )

    report = AuditReport(
        report_type="ct_monitor",
        generated_at=datetime.now(UTC),
        parameters={},
        results=[audit_res],
        ct_result=ct_result,
    )

    sarif_str = export_sarif(report)
    doc = json.loads(sarif_str)

    assert doc["version"] == "2.1.0"
    assert "https://docs.oasis-open.org/sarif/sarif/v2.1.0" in doc["$schema"]
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-ssl-tracker"

    rule_ids = {r["id"] for r in driver["rules"]}
    assert "CT-ROGUE-001" in rule_ids

    results = doc["runs"][0]["results"]
    assert any(r["ruleId"] == "CT-ROGUE-001" and r["level"] == "error" for r in results)
