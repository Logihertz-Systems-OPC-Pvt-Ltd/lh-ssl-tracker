# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        tests.test_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for endpoint network scanner with socket mocking."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

from lh_ssl_tracker.scanner import EndpointScanner, load_targets, parse_target


def test_parse_target() -> None:
    """Test target string parsing across various URL and host formats."""
    assert parse_target("example.com") == ("example.com", 443)
    assert parse_target("example.com:8443") == ("example.com", 8443)
    assert parse_target("https://api.example.com/health") == ("api.example.com", 443)
    assert parse_target("http://test.internal:8080/v1") == ("test.internal", 8080)
    assert parse_target("[::1]:8443") == ("::1", 8443)


def test_load_targets_inventory(tmp_path: Path) -> None:
    """Test inventory target loading from file, commas, and single targets."""
    # From comma string
    assert load_targets("a.com, b.com:443 , c.com") == ["a.com", "b.com:443", "c.com"]

    # From file
    inv_file = tmp_path / "targets.txt"
    inv_file.write_text(
        "# Production endpoints\n"
        "prod1.example.com:443\n\n"
        "prod2.example.com\n"
        "# Internal\n"
        "int.example.com:8443\n",
        encoding="utf-8",
    )
    loaded = load_targets(str(inv_file))
    assert loaded == ["prod1.example.com:443", "prod2.example.com", "int.example.com:8443"]


@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_scanner_fetch_success(
    mock_ctx_factory: MagicMock,
    mock_connect: MagicMock,
    valid_cert_pem: str,
) -> None:
    """Test successful TLS certificate retrieval via mocked socket."""
    from lh_ssl_tracker.certificate import extract_pem_blocks

    der_bytes = extract_pem_blocks(valid_cert_pem)[0]

    mock_sock = MagicMock()
    mock_connect.return_value.__enter__.return_value = mock_sock

    mock_tls_sock = MagicMock()
    mock_tls_sock.getpeercert.return_value = der_bytes
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_tls_sock
    mock_ctx_factory.return_value = mock_ctx

    scanner = EndpointScanner(timeout=5.0)
    cert, err = scanner.scan_endpoint("app.example.com:443")

    assert err is None
    assert cert is not None
    assert cert.common_name == "app.example.com"
    mock_connect.assert_called_once_with(("app.example.com", 443), timeout=5.0)


@patch("socket.create_connection")
def test_scanner_timeout_failure(mock_connect: MagicMock) -> None:
    """Test handling of socket connection timeout."""
    mock_connect.side_effect = TimeoutError("Timed out")

    scanner = EndpointScanner(timeout=2.0)
    cert, err = scanner.scan_endpoint("slow.example.com:443")

    assert cert is None
    assert err is not None
    assert "timed out after 2.0s" in err


@patch("socket.create_connection")
def test_scanner_dns_failure(mock_connect: MagicMock) -> None:
    """Test handling of DNS name resolution failure."""
    mock_connect.side_effect = socket.gaierror(-3, "Temporary failure in name resolution")

    scanner = EndpointScanner()
    cert, err = scanner.scan_endpoint("nonexistent.invalid:443")

    assert cert is None
    assert err is not None
    assert "DNS resolution failure" in err
