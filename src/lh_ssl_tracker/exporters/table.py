# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        src.lh_ssl_tracker.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table exporter for audit reports.

Renders formatted tables, status badges, and metric summary panels
for certificate audits and Certificate Transparency monitoring.
"""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_ssl_tracker.models import AuditReport, FindingSeverity


def _get_status_badge(status: str) -> Text:
    """Return styled Rich Text badge for a given status."""
    st = status.upper()
    if st == "OK":
        return Text("● PASS", style="bold green")
    elif st == "WARNING":
        return Text("▲ WARN", style="bold yellow")
    elif st == "CRITICAL":
        return Text("✖ CRIT", style="bold red")
    elif st == "EXPIRED":
        return Text("✖ EXPIRED", style="bold white on red")
    elif st == "ERROR":
        return Text("✖ ERROR", style="bold magenta")
    return Text(st, style="bold")


def _get_severity_badge(severity: FindingSeverity) -> Text:
    """Return styled Rich Text badge for finding severity."""
    if severity == FindingSeverity.CRITICAL:
        return Text("CRITICAL", style="bold red")
    elif severity == FindingSeverity.HIGH:
        return Text("HIGH", style="bold red")
    elif severity == FindingSeverity.WARNING:
        return Text("WARNING", style="bold yellow")
    elif severity in (FindingSeverity.NOTE, FindingSeverity.INFO):
        return Text("NOTE", style="bold cyan")
    return Text(severity.value, style="bold")


def render_table_report(report: AuditReport, console: Console | None = None) -> str:
    """Render complete AuditReport to a Rich terminal string or print directly.

    Args:
        report: AuditReport instance to render.
        console: Optional Console instance. If None, captures to string.

    Returns:
        Rendered string output.
    """
    report.compute_summary()
    string_io = io.StringIO()
    # Use record=True or capture to return string
    target_console = console or Console(file=string_io, color_system="auto", width=120)

    # Header Panel
    title = f"lh-ssl-tracker: {report.report_type.replace('_', ' ').title()}"
    subtitle = f"Generated at {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    target_console.print(
        Panel(
            Text(f"{title}\n{subtitle}", justify="center", style="bold blue"),
            border_style="blue",
        )
    )

    # Render CT Monitor Results if present
    if report.ct_result:
        ct = report.ct_result
        ct_summary_table = Table(title="Certificate Transparency Summary", border_style="cyan")
        ct_summary_table.add_column("Monitored Domain", style="bold white")
        ct_summary_table.add_column("Total Entries", justify="right")
        ct_summary_table.add_column("Allowlist Rules", justify="right")
        ct_summary_table.add_column("Rogue Subdomains Found", justify="right")

        rogue_count_style = "bold red" if ct.rogue_subdomains else "bold green"
        ct_summary_table.add_row(
            ct.domain,
            str(ct.total_entries),
            str(ct.allowed_subdomains_count),
            f"[{rogue_count_style}]{len(ct.rogue_subdomains)}[/{rogue_count_style}]",
        )
        target_console.print(ct_summary_table)

        if ct.rogue_subdomains:
            rogue_table = Table(
                title=f"Rogue / Shadow Subdomains Detected ({len(ct.rogue_subdomains)})",
                border_style="red",
            )
            rogue_table.add_column("Subdomain", style="bold red")
            rogue_table.add_column("Severity")
            rogue_table.add_column("Rule ID")
            rogue_table.add_column("Details")

            for finding in ct.findings:
                if finding.category.value == "ROGUE_SUBDOMAIN":
                    rogue_table.add_row(
                        finding.target,
                        _get_severity_badge(finding.severity),
                        finding.rule_id,
                        finding.message,
                    )
            target_console.print(rogue_table)
        else:
            target_console.print(
                Panel(
                    "[bold green]✔ All subdomains in CT log match the allowlist.[/bold green]",
                    border_style="green",
                )
            )

    # Render Endpoint / Certificate Results if present
    if report.results:
        cert_table = Table(
            title=f"Certificate Inventory Audit ({len(report.results)} targets)",
            border_style="blue",
            expand=True,
        )
        cert_table.add_column("Target / Host", style="bold white", no_wrap=True)
        cert_table.add_column("Status", justify="center")
        cert_table.add_column("Days Left", justify="right")
        cert_table.add_column("Expires On (UTC)", no_wrap=True)
        cert_table.add_column("Key & Signature", no_wrap=True)
        cert_table.add_column("Issuer Common Name")
        cert_table.add_column("Findings / Violations")

        for r in report.results:
            status_badge = _get_status_badge(r.status)
            if r.certificate:
                cert = r.certificate
                days_text = f"{r.days_remaining:.1f}d"
                expires_str = cert.not_after.strftime("%Y-%m-%d")
                key_sig = (
                    f"{cert.public_key_type} {cert.public_key_bits}b / "
                    f"{cert.signature_algorithm_name[:18]}"
                )
                issuer_str = cert.issuer_common_name or cert.issuer.get("O", "Unknown")
            else:
                days_text = "-"
                expires_str = "-"
                key_sig = "-"
                issuer_str = "-"

            findings_summary = ""
            if r.error_message:
                findings_summary = f"[red]{r.error_message}[/red]"
            elif r.findings:
                bullet_points = [
                    f"[{f.severity.lower()}]{f.rule_id}[/{f.severity.lower()}]: {f.title}"
                    for f in r.findings
                ]
                findings_summary = "\n".join(bullet_points)
            else:
                findings_summary = "[green]Valid & Compliant[/green]"

            cert_table.add_row(
                r.target,
                status_badge,
                days_text,
                expires_str,
                key_sig,
                issuer_str,
                findings_summary,
            )

        target_console.print(cert_table)

    # Summary Panel
    s = report.summary
    summary_text = (
        f"[bold]Targets Audited:[/bold] {s.get('total_targets', 0)}   "
        f"[bold green]Passed:[/bold green] {s.get('passed', 0)}   "
        f"[bold yellow]Warnings:[/bold yellow] {s.get('warning', 0)}   "
        f"[bold red]Critical / Expired:[/bold red] {s.get('critical', 0) + s.get('failed', 0)}   "
        f"[bold]Total Findings:[/bold] {s.get('total_findings', 0)}"
    )
    border = "red" if report.has_critical_findings() else "green"
    target_console.print(Panel(summary_text, title="Audit Summary", border_style=border))

    return string_io.getvalue()
