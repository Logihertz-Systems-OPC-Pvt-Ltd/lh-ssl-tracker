"""Command-line interface for lh-ssl-tracker.

Implements CLI commands:
- lh-ssl check <target>
- lh-ssl monitor-ct <domain>
- lh-ssl audit-bundle <pem-file>
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lh_ssl_tracker.analyzer import CertificateAnalyzer
from lh_ssl_tracker.certificate import parse_pem_bundle
from lh_ssl_tracker.ct_monitor import CertificateTransparencyMonitor
from lh_ssl_tracker.exporters import OutputFormat, export_json, export_sarif, render_table_report
from lh_ssl_tracker.models import (
    AuditReport,
    CertificateAuditResult,
    Finding,
    FindingCategory,
    FindingSeverity,
)
from lh_ssl_tracker.scanner import EndpointScanner, load_targets

app = typer.Typer(
    name="lh-ssl",
    help="Enterprise TLS/SSL Certificate Tracker & CT Monitor by Logihertz Systems OPC Pvt Ltd.",
    no_args_is_help=True,
)
console = Console()


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination.

    Args:
        report: The AuditReport to export.
        fmt: Desired OutputFormat.
        output_path: Target file path or None for standard output.
    """
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        # Table format
        if output_path:
            # File output: render without ANSI formatting for clean text
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            # Terminal output: print directly with full colors
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        # Print JSON/SARIF string to stdout
        print(rendered)


@app.command(name="check")
def check(
    target: Annotated[
        str,
        typer.Argument(
            help="Target endpoint (host:port) or inventory file path containing targets."
        ),
    ],
    warn_days: Annotated[
        int,
        typer.Option("--warn-days", "-w", help="Warning threshold in days before expiration."),
    ] = 30,
    crit_days: Annotated[
        int,
        typer.Option("--crit-days", "-c", help="Critical threshold in days before expiration."),
    ] = 7,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Connection timeout in seconds."),
    ] = 10.0,
) -> None:
    """Inspect live TLS endpoints for expiration, cryptographic strength, and SAN mismatches."""
    targets = load_targets(target)
    if not targets:
        console.print(f"[red]Error: No valid targets found in '{target}'[/red]")
        raise typer.Exit(code=2)

    scanner = EndpointScanner(timeout=timeout)
    analyzer = CertificateAnalyzer(warn_days=warn_days, crit_days=crit_days)
    results: list[CertificateAuditResult] = []

    for tgt in targets:
        cert, err = scanner.scan_endpoint(tgt)
        if err or cert is None:
            finding = Finding(
                rule_id="SSL-CONN-001",
                title="TLS Connection Failure",
                category=FindingCategory.CONNECTION,
                severity=FindingSeverity.CRITICAL,
                target=tgt,
                message=f"Failed to establish TLS handshake with {tgt}: {err}",
                details={"error": err},
            )
            results.append(
                CertificateAuditResult(
                    target=tgt,
                    status="ERROR",
                    error_message=err,
                    findings=[finding],
                )
            )
        else:
            audit_result = analyzer.analyze(cert, target=tgt, target_hostname=tgt)
            results.append(audit_result)

    report = AuditReport(
        report_type="endpoint_check",
        generated_at=datetime.now(UTC),
        parameters={
            "target": target,
            "warn_days": warn_days,
            "crit_days": crit_days,
            "format": format.value,
        },
        results=results,
    )

    _output_report(report, format, output)

    if report.has_critical_findings():
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="monitor-ct")
def monitor_ct(
    domain: Annotated[
        str,
        typer.Argument(help="Target root domain to audit in Certificate Transparency logs."),
    ],
    ct_feed: Annotated[
        Path,
        typer.Option(
            "--ct-feed",
            help="Path to Certificate Transparency log JSON feed (e.g., crt.sh snapshot).",
        ),
    ],
    allowlist: Annotated[
        Path,
        typer.Option(
            "--allowlist",
            help="Path to approved asset allowlist file containing authorized subdomains.",
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
) -> None:
    """Analyze Certificate Transparency log JSON feeds to detect shadow subdomains and rogue CAs."""
    if not ct_feed.is_file():
        console.print(f"[red]Error: CT feed file not found: {ct_feed}[/red]")
        raise typer.Exit(code=2)
    if not allowlist.is_file():
        console.print(f"[red]Error: Allowlist file not found: {allowlist}[/red]")
        raise typer.Exit(code=2)

    try:
        monitor = CertificateTransparencyMonitor()
        ct_result = monitor.analyze(domain, ct_feed, allowlist)
    except Exception as exc:
        console.print(f"[red]Error analyzing CT feed: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    report = AuditReport(
        report_type="ct_monitor",
        generated_at=datetime.now(UTC),
        parameters={
            "domain": domain,
            "ct_feed": str(ct_feed),
            "allowlist": str(allowlist),
            "format": format.value,
        },
        ct_result=ct_result,
    )

    _output_report(report, format, output)

    if report.has_critical_findings():
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="audit-bundle")
def audit_bundle(
    pem_file: Annotated[
        Path,
        typer.Argument(help="Path to PEM certificate file or bundle to audit."),
    ],
    warn_days: Annotated[
        int,
        typer.Option("--warn-days", "-w", help="Warning threshold in days before expiration."),
    ] = 30,
    crit_days: Annotated[
        int,
        typer.Option("--crit-days", "-c", help="Critical threshold in days before expiration."),
    ] = 7,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
) -> None:
    """Audit local PEM certificate bundles for expiration, weak crypto parameters, and policies."""
    if not pem_file.is_file():
        console.print(f"[red]Error: PEM file not found: {pem_file}[/red]")
        raise typer.Exit(code=2)

    try:
        content = pem_file.read_text(encoding="utf-8")
        certs = parse_pem_bundle(content)
    except Exception as exc:
        console.print(f"[red]Error reading PEM bundle: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    if not certs:
        console.print(f"[red]Error: No valid PEM certificates found in '{pem_file}'[/red]")
        raise typer.Exit(code=2)

    analyzer = CertificateAnalyzer(warn_days=warn_days, crit_days=crit_days)
    results: list[CertificateAuditResult] = []

    for i, cert in enumerate(certs):
        label = f"{cert.common_name or 'Cert-' + str(i + 1)} ({cert.serial_number[:8]})"
        audit_res = analyzer.analyze(cert, target=label)
        results.append(audit_res)

    report = AuditReport(
        report_type="bundle_audit",
        generated_at=datetime.now(UTC),
        parameters={
            "pem_file": str(pem_file),
            "warn_days": warn_days,
            "crit_days": crit_days,
            "format": format.value,
        },
        results=results,
    )

    _output_report(report, format, output)

    if report.has_critical_findings():
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
