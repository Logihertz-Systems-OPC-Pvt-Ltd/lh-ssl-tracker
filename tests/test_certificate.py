"""Unit tests for X.509 certificate parsing and PEM extraction."""

from __future__ import annotations

import pytest

from lh_ssl_tracker.certificate import (
    extract_pem_blocks,
    parse_der_certificate,
    parse_pem_bundle,
)


def test_parse_valid_certificate(valid_cert_pem: str) -> None:
    """Test extracting fields from a standard 2048-bit RSA certificate."""
    certs = parse_pem_bundle(valid_cert_pem)
    assert len(certs) == 1
    cert = certs[0]

    assert cert.common_name == "app.example.com"
    assert cert.subject.get("O") == "Logihertz"
    assert cert.issuer_common_name == "app.example.com"
    assert cert.is_self_signed is True
    assert cert.public_key_type == "RSA"
    assert cert.public_key_bits >= 2048
    assert "app.example.com" in cert.subject_alt_names
    assert "api.example.com" in cert.subject_alt_names
    assert "192.168.1.10" in cert.subject_alt_names
    assert len(cert.fingerprint_sha256) == 64
    assert cert.not_before < cert.not_after


def test_parse_ec_certificate(ec_cert_pem: str) -> None:
    """Test parsing an Elliptic Curve certificate."""
    certs = parse_pem_bundle(ec_cert_pem)
    assert len(certs) == 1
    cert = certs[0]

    assert cert.common_name == "secure.example.com"
    assert cert.public_key_type == "EC"
    assert cert.public_key_bits == 256
    assert "*.example.com" in cert.subject_alt_names


def test_parse_weak_rsa_certificate(weak_rsa_cert_pem: str) -> None:
    """Test parsing a 1024-bit RSA certificate."""
    certs = parse_pem_bundle(weak_rsa_cert_pem)
    assert len(certs) == 1
    cert = certs[0]

    assert cert.public_key_type == "RSA"
    assert cert.public_key_bits == 1024


def test_parse_pem_bundle_multiple(valid_cert_pem: str, ec_cert_pem: str) -> None:
    """Test parsing a bundle containing multiple certificates."""
    bundle = f"{valid_cert_pem}\n\n# Some comment\n\n{ec_cert_pem}"
    certs = parse_pem_bundle(bundle)
    assert len(certs) == 2
    assert certs[0].common_name == "app.example.com"
    assert certs[1].common_name == "secure.example.com"


def test_extract_pem_blocks_malformed() -> None:
    """Test handling of corrupt or empty PEM data."""
    assert extract_pem_blocks("") == []
    assert extract_pem_blocks("Not a PEM block") == []
    assert (
        extract_pem_blocks(
            "-----BEGIN CERTIFICATE-----\nInvalidBase64!@#\n-----END CERTIFICATE-----"
        )
        == []
    )


def test_parse_der_invalid() -> None:
    """Test error handling when feeding non-X.509 DER to parse_der_certificate."""
    with pytest.raises(ValueError, match="Root is not a SEQUENCE"):
        parse_der_certificate(b"\x02\x01\x05")

    with pytest.raises(ValueError, match="Insufficient elements"):
        parse_der_certificate(b"\x30\x02\x05\x00")
