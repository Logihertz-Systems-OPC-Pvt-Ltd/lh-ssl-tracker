"""Certificate Transparency (CT) log monitor and shadow subdomain detector.

Parses CT log JSON feeds (crt.sh schema and generic snapshots) and audits
issued certificates against approved asset allowlists to detect rogue subdomains,
unexpected Certificate Authorities, and unmanaged public assets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lh_ssl_tracker.analyzer import matches_hostname
from lh_ssl_tracker.models import CTAuditResult, Finding, FindingCategory, FindingSeverity


def load_allowlist(allowlist_path: Path | str) -> set[str]:
    """Load approved domain patterns from an allowlist file.

    Args:
        allowlist_path: Path to text file with approved domains (one per line).

    Returns:
        Set of normalized lowercase domain patterns.
    """
    path = Path(allowlist_path)
    if not path.is_file():
        raise FileNotFoundError(f"Allowlist file not found: {allowlist_path}")

    patterns: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            patterns.add(line.rstrip("."))
    return patterns


def load_ct_feed(feed_path: Path | str) -> list[dict[str, Any]]:
    """Load Certificate Transparency log entries from a JSON file.

    Supports crt.sh output JSON arrays and nested entries formats.

    Args:
        feed_path: Path to CT log JSON file.

    Returns:
        List of certificate entry dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If JSON syntax or schema is invalid.
    """
    path = Path(feed_path)
    if not path.is_file():
        raise FileNotFoundError(f"CT log feed file not found: {feed_path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in CT feed file: {exc}") from exc

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    elif isinstance(data, dict):
        if "entries" in data and isinstance(data["entries"], list):
            return [item for item in data["entries"] if isinstance(item, dict)]
        return [data]

    raise ValueError("CT feed must be a JSON array or object with an 'entries' list")


def extract_domains_from_entry(entry: dict[str, Any]) -> set[str]:
    """Extract all unique domain names from a CT log entry record.

    Handles crt.sh 'name_value' (newline-separated), 'common_name',
    and generic 'dns_names' / 'san' / 'domains' fields.

    Args:
        entry: Single CT record dictionary.

    Returns:
        Set of lowercase domain names.
    """
    domains: set[str] = set()

    # crt.sh common_name
    cn = entry.get("common_name")
    if cn and isinstance(cn, str):
        domains.add(cn.strip().lower().rstrip("."))

    # crt.sh name_value (often contains multiple domains separated by newlines)
    name_value = entry.get("name_value")
    if name_value and isinstance(name_value, str):
        for part in name_value.splitlines():
            part = part.strip().lower().rstrip(".")
            if part:
                domains.add(part)

    # Generic alternative fields
    for field_name in ("domains", "dns_names", "san", "subject_alt_names"):
        val = entry.get(field_name)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    domains.add(item.strip().lower().rstrip("."))
        elif isinstance(val, str) and val.strip():
            domains.add(val.strip().lower().rstrip("."))

    return domains


def is_domain_in_scope(candidate: str, root_domain: str) -> bool:
    """Check if a domain candidate is the root domain or a subdomain of it.

    Args:
        candidate: Domain to test (e.g., 'sub.example.com').
        root_domain: Monitored root domain (e.g., 'example.com').

    Returns:
        True if candidate is identical or ends with '.{root_domain}'.
    """
    cand = candidate.lstrip("*.").lower()
    root = root_domain.lower().rstrip(".")

    return cand == root or cand.endswith("." + root)


def is_allowed(candidate: str, allowlist: set[str]) -> bool:
    """Determine whether a candidate domain is permitted by the allowlist patterns.

    Args:
        candidate: Candidate domain string.
        allowlist: Set of approved domain patterns.

    Returns:
        True if permitted, False otherwise.
    """
    cand = candidate.lower().rstrip(".")

    for pattern in allowlist:
        pat = pattern.lower().rstrip(".")
        if matches_hostname(cand, pat):
            return True

    return False


class CertificateTransparencyMonitor:
    """Monitors Certificate Transparency log feeds and detects shadow subdomains."""

    def __init__(self, allowed_cas: set[str] | None = None) -> None:
        """Initialize CT monitor with optional allowed Certificate Authorities.

        Args:
            allowed_cas: Set of permitted CA issuer names/substrings, or None for any.
        """
        self.allowed_cas = {ca.lower() for ca in allowed_cas} if allowed_cas else None

    def analyze(
        self,
        domain: str,
        ct_feed_path: Path | str,
        allowlist_path: Path | str,
    ) -> CTAuditResult:
        """Analyze a CT log feed for a domain against an allowlist.

        Args:
            domain: Target root domain to audit.
            ct_feed_path: Path to CT log JSON file.
            allowlist_path: Path to approved subdomains text file.

        Returns:
            CTAuditResult with detected rogue subdomains and findings.
        """
        allowlist = load_allowlist(allowlist_path)
        entries = load_ct_feed(ct_feed_path)

        clean_domain = domain.strip().lower().rstrip(".")
        findings: list[Finding] = []
        rogue_subdomains: set[str] = set()
        analyzed_entries: list[dict[str, Any]] = []

        for entry in entries:
            domains_in_entry = extract_domains_from_entry(entry)
            issuer = str(entry.get("issuer_name") or entry.get("issuer") or "Unknown CA")
            not_after_str = str(entry.get("not_after") or entry.get("valid_to") or "")
            entry_id = str(entry.get("id") or entry.get("serial_number") or "N/A")

            # Check domain scope
            in_scope_domains = {d for d in domains_in_entry if is_domain_in_scope(d, clean_domain)}
            if not in_scope_domains:
                continue

            entry_summary = {
                "id": entry_id,
                "issuer": issuer,
                "domains": sorted(in_scope_domains),
                "not_after": not_after_str,
            }
            analyzed_entries.append(entry_summary)

            # 1. Check for Rogue / Shadow Subdomains
            for sub in sorted(in_scope_domains):
                if not is_allowed(sub, allowlist):
                    rogue_subdomains.add(sub)
                    findings.append(
                        Finding(
                            rule_id="CT-ROGUE-001",
                            title="Rogue / Shadow Subdomain Detected in CT Logs",
                            category=FindingCategory.ROGUE_SUBDOMAIN,
                            severity=FindingSeverity.HIGH,
                            target=sub,
                            message=(
                                f"Unauthorized domain '{sub}' found in CT logs issued by "
                                f"'{issuer}'. Domain is absent from approved asset allowlist."
                            ),
                            details={
                                "subdomain": sub,
                                "issuer": issuer,
                                "ct_entry_id": entry_id,
                                "not_after": not_after_str,
                            },
                        )
                    )

            # 2. Check for Unexpected CA
            if self.allowed_cas:
                issuer_lower = issuer.lower()
                ca_matched = any(ca in issuer_lower for ca in self.allowed_cas)
                if not ca_matched:
                    findings.append(
                        Finding(
                            rule_id="CT-UNEXPECTED-CA-001",
                            title="Unexpected Certificate Authority in CT Logs",
                            category=FindingCategory.UNEXPECTED_CA,
                            severity=FindingSeverity.WARNING,
                            target=clean_domain,
                            message=(
                                f"Certificate for {sorted(in_scope_domains)} was issued "
                                f"by unexpected CA '{issuer}' not present in approved CA list."
                            ),
                            details={
                                "issuer": issuer,
                                "ct_entry_id": entry_id,
                                "domains": sorted(in_scope_domains),
                            },
                        )
                    )

        return CTAuditResult(
            domain=clean_domain,
            total_entries=len(entries),
            allowed_subdomains_count=len(allowlist),
            rogue_subdomains=sorted(rogue_subdomains),
            findings=findings,
            entries_analyzed=analyzed_entries,
        )
