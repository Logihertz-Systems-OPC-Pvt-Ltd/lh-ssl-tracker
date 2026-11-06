# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        tests.test_coverage_boost
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Additional targeted unit tests to ensure high test coverage across all modules."""

from __future__ import annotations

from datetime import UTC, datetime

from lh_ssl_tracker.asn1 import TAG_BOOLEAN, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, ASN1Node
from lh_ssl_tracker.certificate import _parse_extensions, _parse_spki
from lh_ssl_tracker.exporters.table import (
    _get_severity_badge,
    _get_status_badge,
    render_table_report,
)
from lh_ssl_tracker.models import (
    AuditReport,
    CertificateAuditResult,
    CTAuditResult,
    Finding,
    FindingCategory,
    FindingSeverity,
    ParsedCertificate,
)


def test_models_to_dict() -> None:
    """Test serialization of data models to dictionaries."""
    now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
    cert = ParsedCertificate(
        fingerprint_sha256="F" * 64,
        serial_number="A1B2",
        subject={"CN": "test.com"},
        issuer={"CN": "Test CA"},
        common_name="test.com",
        issuer_common_name="Test CA",
        not_before=now,
        not_after=now,
        signature_algorithm_oid="1.2.840.113549.1.1.11",
        signature_algorithm_name="sha256WithRSAEncryption",
        public_key_type="RSA",
        public_key_bits=2048,
        subject_alt_names=["test.com"],
        is_self_signed=False,
        is_ca=True,
    )
    d = cert.to_dict()
    assert d["common_name"] == "test.com"
    assert d["is_ca"] is True

    finding = Finding(
        rule_id="TEST-001",
        title="Test Title",
        category=FindingCategory.POLICY,
        severity=FindingSeverity.NOTE,
        target="test.com",
        message="A test message",
        details={"foo": "bar"},
    )
    fd = finding.to_dict()
    assert fd["rule_id"] == "TEST-001"
    assert fd["severity"] == "NOTE"

    audit_res = CertificateAuditResult(
        target="test.com",
        certificate=cert,
        days_remaining=10.5,
        status="WARNING",
        findings=[finding],
    )
    ad = audit_res.to_dict()
    assert ad["status"] == "WARNING"
    assert ad["days_remaining"] == 10.5

    ct_res = CTAuditResult(
        domain="test.com",
        total_entries=5,
        allowed_subdomains_count=3,
        rogue_subdomains=["rogue.test.com"],
        findings=[finding],
    )
    ctd = ct_res.to_dict()
    assert ctd["domain"] == "test.com"
    assert len(ctd["rogue_subdomains"]) == 1


def test_spki_alternative_key_types() -> None:
    """Test SPKI parser for Ed25519, Ed448, and DSA."""
    # Ed25519 OID: 1.3.101.112
    oid_bytes = bytes([0x2B, 0x65, 0x70])  # 1.3.101.112
    alg_node = ASN1Node(
        tag=TAG_SEQUENCE, data=b"", children=[ASN1Node(tag=TAG_OID, data=oid_bytes)]
    )
    bit_str_node = ASN1Node(tag=0x03, data=b"\x00" + b"\x01" * 32)
    spki_node = ASN1Node(tag=TAG_SEQUENCE, data=b"", children=[alg_node, bit_str_node])

    key_type, bits = _parse_spki(spki_node)
    assert key_type == "Ed25519"
    assert bits == 256

    # Ed448 OID: 1.3.101.113
    oid_448 = bytes([0x2B, 0x65, 0x71])
    alg_448 = ASN1Node(tag=TAG_SEQUENCE, data=b"", children=[ASN1Node(tag=TAG_OID, data=oid_448)])
    spki_448 = ASN1Node(tag=TAG_SEQUENCE, data=b"", children=[alg_448, bit_str_node])
    k448, b448 = _parse_spki(spki_448)
    assert k448 == "Ed448"
    assert b448 == 448

    # Incomplete node
    assert _parse_spki(ASN1Node(tag=TAG_SEQUENCE, data=b"", children=[])) == ("Unknown", 0)


def test_extensions_ipv6_and_basic_constraints() -> None:
    """Test IPv6 SAN parsing and BasicConstraints CA flag."""
    # IPv6 payload: 16 bytes: 2001:0db8::1
    ip6_bytes = bytes.fromhex("20010db8000000000000000000000001")
    gen_name_ip6 = ASN1Node(tag=0x87, data=ip6_bytes)  # [7] IMPLICIT
    ASN1Node(tag=TAG_SEQUENCE, data=b"", children=[gen_name_ip6])
    san_octets = bytes([TAG_SEQUENCE, len(ip6_bytes) + 2, 0x87, len(ip6_bytes)]) + ip6_bytes

    san_ext = ASN1Node(
        tag=TAG_SEQUENCE,
        data=b"",
        children=[
            ASN1Node(tag=TAG_OID, data=bytes([0x55, 0x1D, 0x11])),  # 2.5.29.17
            ASN1Node(tag=TAG_OCTET_STRING, data=san_octets),
        ],
    )

    # BasicConstraints CA=True
    bc_octets = bytes([TAG_SEQUENCE, 0x03, TAG_BOOLEAN, 0x01, 0xFF])
    bc_ext = ASN1Node(
        tag=TAG_SEQUENCE,
        data=b"",
        children=[
            ASN1Node(tag=TAG_OID, data=bytes([0x55, 0x1D, 0x13])),  # 2.5.29.19
            ASN1Node(tag=TAG_OCTET_STRING, data=bc_octets),
        ],
    )

    exts_node = ASN1Node(tag=TAG_SEQUENCE, data=b"", children=[san_ext, bc_ext])
    sans, is_ca = _parse_extensions(exts_node)

    assert is_ca is True
    assert len(sans) == 1
    assert "2001:0db8" in sans[0]


def test_table_badges_and_statuses() -> None:
    """Test helper status and severity badge renders in table exporter."""
    assert "EXPIRED" in _get_status_badge("EXPIRED").plain
    assert "CRIT" in _get_status_badge("CRITICAL").plain
    assert "ERROR" in _get_status_badge("ERROR").plain
    assert "UNKNOWN" in _get_status_badge("UNKNOWN").plain

    assert "NOTE" in _get_severity_badge(FindingSeverity.NOTE).plain
    assert "NOTE" in _get_severity_badge(FindingSeverity.INFO).plain

    # Render report with error message and CT findings
    now = datetime.now(UTC)
    err_res = CertificateAuditResult(target="fail.local", status="ERROR", error_message="Refused")
    finding = Finding(
        rule_id="CT-ROGUE-001",
        title="Rogue",
        category=FindingCategory.ROGUE_SUBDOMAIN,
        severity=FindingSeverity.HIGH,
        target="rogue.test.com",
        message="Unauthorized",
    )
    ct_res = CTAuditResult(
        domain="test.com",
        total_entries=1,
        allowed_subdomains_count=0,
        rogue_subdomains=["rogue.test.com"],
        findings=[finding],
    )
    report = AuditReport(
        report_type="endpoint_check",
        generated_at=now,
        parameters={},
        results=[err_res],
        ct_result=ct_res,
    )
    rendered = render_table_report(report)
    assert "Refused" in rendered
    assert "rogue.test.com" in rendered
