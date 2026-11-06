# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures and sample certificates."""

from __future__ import annotations

import subprocess

import pytest


@pytest.fixture(scope="session")
def valid_cert_pem() -> str:
    """Generate a standard valid 2048-bit RSA self-signed certificate."""
    return subprocess.check_output(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "/dev/null",
            "-nodes",
            "-days",
            "365",
            "-subj",
            "/CN=app.example.com/O=Logihertz",
            "-addext",
            "subjectAltName=DNS:app.example.com,DNS:api.example.com,IP:192.168.1.10",
        ],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8")


@pytest.fixture(scope="session")
def weak_rsa_cert_pem() -> str:
    """Generate a 1024-bit RSA certificate (weak key length)."""
    return subprocess.check_output(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:1024",
            "-keyout",
            "/dev/null",
            "-nodes",
            "-days",
            "90",
            "-subj",
            "/CN=legacy.example.com/O=Legacy Dept",
        ],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8")


@pytest.fixture(scope="session")
def ec_cert_pem() -> str:
    """Generate an EC P-256 certificate."""
    return subprocess.check_output(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
            "/dev/null",
            "-nodes",
            "-days",
            "60",
            "-subj",
            "/CN=secure.example.com",
            "-addext",
            "subjectAltName=DNS:secure.example.com,DNS:*.example.com",
        ],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8")


@pytest.fixture(scope="session")
def md5_cert_pem() -> str:
    """Generate a certificate with MD5 signature algorithm."""
    # OpenSSL 3 disables MD5 by default in default provider, but we can test
    # either with legacy or generate custom DER or test sha1
    try:
        return subprocess.check_output(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                "/dev/null",
                "-nodes",
                "-days",
                "30",
                "-md5",
                "-subj",
                "/CN=md5.example.com",
            ],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8")
    except Exception:
        # Fallback to sha1 if MD5 is completely disabled by system openssl
        return subprocess.check_output(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                "/dev/null",
                "-nodes",
                "-days",
                "30",
                "-sha1",
                "-subj",
                "/CN=sha1.example.com",
            ],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8")
