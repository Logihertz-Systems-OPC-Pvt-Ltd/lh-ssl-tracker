# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        tests.test_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for certificate expiration and cryptographic analyzer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from lh_ssl_tracker.analyzer import CertificateAnalyzer, matches_hostname
from lh_ssl_tracker.certificate import parse_pem_bundle
from lh_ssl_tracker.models import FindingCategory, FindingSeverity, ParsedCertificate


def test_matches_hostname_rfc6125() -> None:
    """Test wildcard and exact domain matching behavior."""
    assert matches_hostname("example.com", "example.com") is True
    assert matches_hostname("EXAMPLE.COM", "example.com") is True
    assert matches_hostname("api.example.com", "*.example.com") is True
    assert matches_hostname("sub.api.example.com", "*.example.com") is False
    assert matches_hostname("example.com", "*.example.com") is False
    assert matches_hostname("other.com", "example.com") is False


def test_analyzer_expiration_thresholds(valid_cert_pem: str) -> None:
    """Test expiration logic against OK, WARNING, CRITICAL, and EXPIRED thresholds."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    analyzer = CertificateAnalyzer(warn_days=30, crit_days=7)

    # 1. Valid (60 days remaining)
    now_valid = cert.not_after - timedelta(days=60)
    res_valid = analyzer.analyze(cert, target="app.example.com", now=now_valid)
    assert res_valid.status == "OK"
    assert not any(f.category == FindingCategory.EXPIRATION for f in res_valid.findings)

    # 2. Warning (15 days remaining)
    now_warn = cert.not_after - timedelta(days=15)
    res_warn = analyzer.analyze(cert, target="app.example.com", now=now_warn)
    assert res_warn.status == "WARNING"
    exp_findings = [f for f in res_warn.findings if f.rule_id == "SSL-EXP-003"]
    assert len(exp_findings) == 1
    assert exp_findings[0].severity == FindingSeverity.WARNING

    # 3. Critical (5 days remaining)
    now_crit = cert.not_after - timedelta(days=5)
    res_crit = analyzer.analyze(cert, target="app.example.com", now=now_crit)
    assert res_crit.status == "CRITICAL"
    exp_crit = [f for f in res_crit.findings if f.rule_id == "SSL-EXP-002"]
    assert len(exp_crit) == 1
    assert exp_crit[0].severity == FindingSeverity.CRITICAL

    # 4. Expired (2 days past)
    now_expired = cert.not_after + timedelta(days=2)
    res_expired = analyzer.analyze(cert, target="app.example.com", now=now_expired)
    assert res_expired.status == "EXPIRED"
    exp_past = [f for f in res_expired.findings if f.rule_id == "SSL-EXP-001"]
    assert len(exp_past) == 1
    assert exp_past[0].severity == FindingSeverity.CRITICAL

    # 5. Not yet valid
    now_early = cert.not_before - timedelta(days=5)
    res_early = analyzer.analyze(cert, target="app.example.com", now=now_early)
    assert res_early.status == "CRITICAL"
    assert any(f.rule_id == "SSL-EXP-004" for f in res_early.findings)


def test_analyzer_weak_crypto_parameters() -> None:
    """Test flagging of weak signature algorithms and key lengths."""
    analyzer = CertificateAnalyzer(warn_days=30, crit_days=7)
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)

    # Mock certificate with MD5 and 1024-bit RSA
    weak_cert = ParsedCertificate(
        fingerprint_sha256="A" * 64,
        serial_number="1234",
        subject={"CN": "legacy.internal"},
        issuer={"CN": "internal-ca"},
        common_name="legacy.internal",
        issuer_common_name="internal-ca",
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=100),
        signature_algorithm_oid="1.2.840.113549.1.1.4",
        signature_algorithm_name="md5WithRSAEncryption",
        public_key_type="RSA",
        public_key_bits=1024,
        subject_alt_names=["legacy.internal"],
        is_self_signed=False,
    )

    result = analyzer.analyze(weak_cert, target="legacy.internal", now=now)
    rule_ids = {f.rule_id for f in result.findings}
    assert "SSL-CRYPTO-001" in rule_ids  # MD5
    assert "SSL-CRYPTO-003" in rule_ids  # RSA 1024 < 2048
    assert result.status == "CRITICAL"


def test_analyzer_sha1_and_weak_ec() -> None:
    """Test SHA-1 signature and weak EC curve detection."""
    analyzer = CertificateAnalyzer(min_ec_bits=224)
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)

    sha1_ec_cert = ParsedCertificate(
        fingerprint_sha256="B" * 64,
        serial_number="5678",
        subject={"CN": "ec-weak.internal"},
        issuer={"CN": "root-ca"},
        common_name="ec-weak.internal",
        issuer_common_name="root-ca",
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=100),
        signature_algorithm_oid="1.2.840.10045.4.1",
        signature_algorithm_name="ecdsa-with-SHA1",
        public_key_type="EC",
        public_key_bits=160,
        subject_alt_names=["ec-weak.internal"],
        is_self_signed=False,
    )

    result = analyzer.analyze(sha1_ec_cert, target="ec-weak.internal", now=now)
    rule_ids = {f.rule_id for f in result.findings}
    assert "SSL-CRYPTO-002" in rule_ids  # SHA-1
    assert "SSL-CRYPTO-004" in rule_ids  # EC 160 < 224


def test_analyzer_hostname_mismatch(valid_cert_pem: str) -> None:
    """Test detection of hostname mismatch against CN and SANs."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    analyzer = CertificateAnalyzer()
    now = cert.not_before + timedelta(days=10)

    # Valid target
    res_good = analyzer.analyze(
        cert, target="api.example.com", target_hostname="api.example.com", now=now
    )
    assert not any(f.rule_id == "SSL-HOST-001" for f in res_good.findings)

    # Mismatch target
    res_bad = analyzer.analyze(
        cert,
        target="unrelated.domain.com:443",
        target_hostname="unrelated.domain.com:443",
        now=now,
    )
    mismatch_findings = [f for f in res_bad.findings if f.rule_id == "SSL-HOST-001"]
    assert len(mismatch_findings) == 1
    assert mismatch_findings[0].severity == FindingSeverity.HIGH
