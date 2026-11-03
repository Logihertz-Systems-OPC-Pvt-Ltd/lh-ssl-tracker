"""Unit tests for Certificate Transparency log monitor."""

from __future__ import annotations

import json
from pathlib import Path

from lh_ssl_tracker.ct_monitor import (
    CertificateTransparencyMonitor,
    extract_domains_from_entry,
    is_allowed,
    is_domain_in_scope,
)
from lh_ssl_tracker.models import FindingSeverity


def test_extract_domains_from_crt_sh() -> None:
    """Test extracting multiple domains from crt.sh name_value multiline string."""
    entry = {
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\napi.example.com\n*.internal.example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    }
    domains = extract_domains_from_entry(entry)
    assert "example.com" in domains
    assert "www.example.com" in domains
    assert "api.example.com" in domains
    assert "*.internal.example.com" in domains


def test_domain_in_scope() -> None:
    """Test scoping domain candidates to the audited root domain."""
    assert is_domain_in_scope("example.com", "example.com") is True
    assert is_domain_in_scope("api.example.com", "example.com") is True
    assert is_domain_in_scope("deep.sub.example.com", "example.com") is True
    assert is_domain_in_scope("other-example.com", "example.com") is False
    assert is_domain_in_scope("google.com", "example.com") is False


def test_is_allowed_patterns() -> None:
    """Test allowlist pattern evaluation."""
    allowlist = {"example.com", "*.example.com", "*.internal.example.com"}
    assert is_allowed("example.com", allowlist) is True
    assert is_allowed("api.example.com", allowlist) is True
    assert is_allowed("db.internal.example.com", allowlist) is True
    assert is_allowed("shadow.deep.example.com", allowlist) is False
    assert is_allowed("rogue.com", allowlist) is False


def test_ct_monitor_detects_rogue_subdomains(tmp_path: Path) -> None:
    """Test CT monitor flagging rogue/shadow subdomains absent from allowlist."""
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text(
        "# Authorized corporate assets\nexample.com\nwww.example.com\napi.example.com\n",
        encoding="utf-8",
    )

    ct_data = [
        {
            "id": 1001,
            "common_name": "api.example.com",
            "name_value": "api.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "not_after": "2027-01-01T00:00:00",
        },
        {
            "id": 1002,
            "common_name": "shadow-portal.example.com",
            "name_value": "shadow-portal.example.com\nsecret-admin.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "not_after": "2027-01-01T00:00:00",
        },
        {
            "id": 1003,
            "common_name": "external-vendor.com",
            "name_value": "external-vendor.com",
            "issuer_name": "C=US, O=DigiCert",
            "not_after": "2027-01-01T00:00:00",
        },
    ]

    feed_file = tmp_path / "ct_feed.json"
    feed_file.write_text(json.dumps(ct_data), encoding="utf-8")

    monitor = CertificateTransparencyMonitor()
    result = monitor.analyze("example.com", feed_file, allowlist_file)

    assert result.domain == "example.com"
    assert "secret-admin.example.com" in result.rogue_subdomains
    assert "shadow-portal.example.com" in result.rogue_subdomains
    assert "api.example.com" not in result.rogue_subdomains
    assert len(result.rogue_subdomains) == 2

    rogue_findings = [f for f in result.findings if f.rule_id == "CT-ROGUE-001"]
    assert len(rogue_findings) == 2
    assert all(f.severity == FindingSeverity.HIGH for f in rogue_findings)


def test_ct_monitor_unexpected_ca(tmp_path: Path) -> None:
    """Test flagging of unexpected CA issuers."""
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text("example.com\napi.example.com\n", encoding="utf-8")

    ct_data = [
        {
            "id": 2001,
            "common_name": "api.example.com",
            "issuer_name": "C=CN, O=Untrusted Rogue CA Ltd, CN=Suspect Root",
            "not_after": "2027-01-01T00:00:00",
        }
    ]
    feed_file = tmp_path / "ct_feed.json"
    feed_file.write_text(json.dumps(ct_data), encoding="utf-8")

    monitor = CertificateTransparencyMonitor(allowed_cas={"Let's Encrypt", "DigiCert"})
    result = monitor.analyze("example.com", feed_file, allowlist_file)

    ca_findings = [f for f in result.findings if f.rule_id == "CT-UNEXPECTED-CA-001"]
    assert len(ca_findings) == 1
    assert "Suspect Root" in ca_findings[0].message
