"""Unit tests for the CLI interface using Typer CliRunner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from lh_ssl_tracker.certificate import parse_pem_bundle
from lh_ssl_tracker.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    """Test CLI top-level and subcommand help commands."""
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "Enterprise TLS/SSL Certificate Tracker" in res.stdout

    res_check = runner.invoke(app, ["check", "--help"])
    assert res_check.exit_code == 0
    assert "--warn-days" in res_check.stdout

    res_ct = runner.invoke(app, ["monitor-ct", "--help"])
    assert res_ct.exit_code == 0
    assert "--ct-feed" in res_ct.stdout

    res_bundle = runner.invoke(app, ["audit-bundle", "--help"])
    assert res_bundle.exit_code == 0
    assert "pem_file" in res_bundle.stdout.lower() or "pem-file" in res_bundle.stdout.lower()


@patch("lh_ssl_tracker.scanner.EndpointScanner.scan_endpoint")
def test_cli_check_clean(mock_scan: patch, valid_cert_pem: str) -> None:
    """Test lh-ssl check on a clean endpoint with exit code 0."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    # Set target to match cert CN
    mock_scan.return_value = (cert, None)

    # Use very low warn/crit days so it passes cleanly
    result = runner.invoke(
        app,
        ["check", "app.example.com", "--warn-days", "1", "--crit-days", "0"],
    )
    # Self-signed creates a WARNING finding, so check should exit 0
    assert result.exit_code == 0
    assert "Passed:" in result.stdout or "PASS" in result.stdout or "OK" in result.stdout


@patch("lh_ssl_tracker.scanner.EndpointScanner.scan_endpoint")
def test_cli_check_json_output(mock_scan: patch, valid_cert_pem: str) -> None:
    """Test lh-ssl check exporting JSON format to stdout."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    mock_scan.return_value = (cert, None)

    result = runner.invoke(
        app,
        ["check", "app.example.com", "--format", "json"],
    )
    # Output should parse as valid JSON
    data = json.loads(result.stdout)
    assert data["report_type"] == "endpoint_check"
    assert len(data["results"]) == 1


@patch("lh_ssl_tracker.scanner.EndpointScanner.scan_endpoint")
def test_cli_check_file_output(
    mock_scan: patch,
    valid_cert_pem: str,
    tmp_path: Path,
) -> None:
    """Test lh-ssl check writing report to output file."""
    cert = parse_pem_bundle(valid_cert_pem)[0]
    mock_scan.return_value = (cert, None)
    out_file = tmp_path / "report.json"

    res = runner.invoke(
        app,
        ["check", "app.example.com", "--format", "json", "--output", str(out_file)],
    )
    assert res.exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["report_type"] == "endpoint_check"


@patch("lh_ssl_tracker.scanner.EndpointScanner.scan_endpoint")
def test_cli_check_connection_error(mock_scan: patch) -> None:
    """Test lh-ssl check handling network failure."""
    mock_scan.return_value = (None, "Connection refused")

    result = runner.invoke(app, ["check", "unreachable.local:443"])
    assert result.exit_code == 1  # Critical finding generated


def test_cli_monitor_ct(tmp_path: Path) -> None:
    """Test lh-ssl monitor-ct detecting rogue subdomains."""
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text("example.com\napi.example.com\n", encoding="utf-8")

    ct_feed_file = tmp_path / "ct.json"
    ct_data = [
        {
            "id": 1,
            "common_name": "api.example.com",
            "name_value": "api.example.com",
            "issuer_name": "C=US, O=DigiCert",
        },
        {
            "id": 2,
            "common_name": "rogue-dev.example.com",
            "name_value": "rogue-dev.example.com",
            "issuer_name": "C=US, O=DigiCert",
        },
    ]
    ct_feed_file.write_text(json.dumps(ct_data), encoding="utf-8")

    out_sarif = tmp_path / "ct.sarif"
    result = runner.invoke(
        app,
        [
            "monitor-ct",
            "example.com",
            "--ct-feed",
            str(ct_feed_file),
            "--allowlist",
            str(allowlist_file),
            "--format",
            "sarif",
            "--output",
            str(out_sarif),
        ],
    )
    # Rogue subdomain detected -> exit code 1
    assert result.exit_code == 1
    assert out_sarif.is_file()
    sarif_data = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"


def test_cli_monitor_ct_clean(tmp_path: Path) -> None:
    """Test lh-ssl monitor-ct when all subdomains are authorized."""
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text("example.com\n*.example.com\n", encoding="utf-8")

    ct_feed_file = tmp_path / "ct.json"
    ct_data = [
        {
            "id": 1,
            "common_name": "api.example.com",
            "name_value": "api.example.com",
            "issuer_name": "C=US, O=DigiCert",
        }
    ]
    ct_feed_file.write_text(json.dumps(ct_data), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "monitor-ct",
            "example.com",
            "--ct-feed",
            str(ct_feed_file),
            "--allowlist",
            str(allowlist_file),
        ],
    )
    assert result.exit_code == 0


def test_cli_monitor_ct_missing_files(tmp_path: Path) -> None:
    """Test error handling when input files are missing."""
    result = runner.invoke(
        app,
        [
            "monitor-ct",
            "example.com",
            "--ct-feed",
            str(tmp_path / "missing_feed.json"),
            "--allowlist",
            str(tmp_path / "missing_allowlist.txt"),
        ],
    )
    assert result.exit_code == 2


def test_cli_audit_bundle(tmp_path: Path, valid_cert_pem: str) -> None:
    """Test auditing a local PEM certificate bundle."""
    bundle_file = tmp_path / "certs.pem"
    bundle_file.write_text(valid_cert_pem, encoding="utf-8")

    result = runner.invoke(
        app,
        ["audit-bundle", str(bundle_file), "--warn-days", "1", "--crit-days", "0"],
    )
    assert result.exit_code == 0
    assert "app.example.com" in result.stdout


def test_cli_audit_bundle_weak_key(tmp_path: Path, weak_rsa_cert_pem: str) -> None:
    """Test auditing a bundle containing a weak 1024-bit RSA key."""
    bundle_file = tmp_path / "weak.pem"
    bundle_file.write_text(weak_rsa_cert_pem, encoding="utf-8")

    result = runner.invoke(app, ["audit-bundle", str(bundle_file)])
    assert result.exit_code == 1  # Weak key is HIGH severity finding


def test_cli_audit_bundle_missing_or_empty(tmp_path: Path) -> None:
    """Test auditing missing file or file without certificates."""
    missing = tmp_path / "nope.pem"
    assert runner.invoke(app, ["audit-bundle", str(missing)]).exit_code == 2

    empty = tmp_path / "empty.pem"
    empty.write_text("Not a cert", encoding="utf-8")
    assert runner.invoke(app, ["audit-bundle", str(empty)]).exit_code == 2
