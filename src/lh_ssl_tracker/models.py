"""Data models and findings representations for lh-ssl-tracker.

Provides structured types for certificates, security findings, severity levels,
and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    """Severity levels for audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    WARNING = "WARNING"
    NOTE = "NOTE"
    INFO = "INFO"


class FindingCategory(StrEnum):
    """Categorization of audit findings."""

    EXPIRATION = "EXPIRATION"
    CRYPTO_STRENGTH = "CRYPTO_STRENGTH"
    HOSTNAME_MISMATCH = "HOSTNAME_MISMATCH"
    ROGUE_SUBDOMAIN = "ROGUE_SUBDOMAIN"
    UNEXPECTED_CA = "UNEXPECTED_CA"
    SLA_VIOLATION = "SLA_VIOLATION"
    POLICY = "POLICY"
    CONNECTION = "CONNECTION"


@dataclass(frozen=True)
class Finding:
    """Represents an individual security or compliance finding.

    Attributes:
        rule_id: Unique rule identifier (e.g., SSL-EXP-001).
        title: Short title summarizing the issue.
        category: Category of the finding.
        severity: Severity level.
        target: Affected target or certificate subject.
        message: Detailed explanation of the finding.
        details: Additional context or technical parameters.
    """

    rule_id: str
    title: str
    category: FindingCategory
    severity: FindingSeverity
    target: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ParsedCertificate:
    """Structured representation of a parsed X.509 certificate.

    Attributes:
        fingerprint_sha256: Hex-encoded SHA-256 fingerprint.
        serial_number: Hex string representation of the serial number.
        subject: Subject distinguished name attributes.
        issuer: Issuer distinguished name attributes.
        common_name: Subject Common Name (CN).
        issuer_common_name: Issuer Common Name (CN).
        not_before: Certificate validity start timestamp (UTC).
        not_after: Certificate validity end timestamp (UTC).
        signature_algorithm_oid: OID of signature algorithm.
        signature_algorithm_name: Human-readable name of signature algorithm.
        public_key_type: Public key algorithm (e.g. RSA, EC, Ed25519).
        public_key_bits: Effective bit length of the public key.
        subject_alt_names: List of Subject Alternative Names (DNS/IP).
        is_self_signed: True if subject equals issuer.
        is_ca: True if certificate is identified as a Certificate Authority.
        raw_pem: Raw PEM-encoded certificate string.
        raw_der: Raw DER-encoded certificate bytes.
    """

    fingerprint_sha256: str
    serial_number: str
    subject: dict[str, str]
    issuer: dict[str, str]
    common_name: str
    issuer_common_name: str
    not_before: datetime
    not_after: datetime
    signature_algorithm_oid: str
    signature_algorithm_name: str
    public_key_type: str
    public_key_bits: int
    subject_alt_names: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_ca: bool = False
    raw_pem: str = ""
    raw_der: bytes = field(default=b"", repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Convert certificate to dictionary representation."""
        return {
            "fingerprint_sha256": self.fingerprint_sha256,
            "serial_number": self.serial_number,
            "subject": self.subject,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "issuer_common_name": self.issuer_common_name,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "signature_algorithm_oid": self.signature_algorithm_oid,
            "signature_algorithm_name": self.signature_algorithm_name,
            "public_key_type": self.public_key_type,
            "public_key_bits": self.public_key_bits,
            "subject_alt_names": self.subject_alt_names,
            "is_self_signed": self.is_self_signed,
            "is_ca": self.is_ca,
        }


@dataclass
class CertificateAuditResult:
    """Audit result for a single certificate or endpoint target.

    Attributes:
        target: Target address or certificate identifier.
        certificate: Parsed certificate details, if successfully obtained.
        days_remaining: Days until expiration (negative if expired).
        status: Overall status (OK, WARNING, CRITICAL, EXPIRED, ERROR).
        findings: List of security/compliance findings.
        error_message: Error string if scan or parse failed.
    """

    target: str
    certificate: ParsedCertificate | None = None
    days_remaining: float = 0.0
    status: str = "OK"
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert audit result to dictionary representation."""
        return {
            "target": self.target,
            "status": self.status,
            "days_remaining": round(self.days_remaining, 1),
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class CTAuditResult:
    """Audit result from Certificate Transparency log inspection.

    Attributes:
        domain: Audited parent domain.
        total_entries: Total log entries analyzed.
        allowed_subdomains_count: Number of unique approved subdomains.
        rogue_subdomains: Unique list of unauthorized or shadow subdomains found.
        findings: List of CT-specific findings.
        entries_analyzed: Detailed CT entries metadata.
    """

    domain: str
    total_entries: int = 0
    allowed_subdomains_count: int = 0
    rogue_subdomains: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entries_analyzed: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert CT audit result to dictionary representation."""
        return {
            "domain": self.domain,
            "total_entries": self.total_entries,
            "allowed_subdomains_count": self.allowed_subdomains_count,
            "rogue_subdomains": self.rogue_subdomains,
            "findings": [f.to_dict() for f in self.findings],
            "entries_analyzed": self.entries_analyzed,
        }


@dataclass
class AuditReport:
    """Top-level report containing all audit results and execution parameters.

    Attributes:
        report_type: Type of audit (endpoint_check, bundle_audit, ct_monitor).
        generated_at: Timestamp when report was produced (UTC).
        parameters: CLI/scan parameters used for execution.
        results: List of endpoint or bundle audit results.
        ct_result: Certificate Transparency audit result (if applicable).
        summary: Aggregated summary statistics.
    """

    report_type: str
    generated_at: datetime
    parameters: dict[str, Any]
    results: list[CertificateAuditResult] = field(default_factory=list)
    ct_result: CTAuditResult | None = None
    summary: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Calculate and store summary statistics."""
        critical_count = 0
        warning_count = 0
        passed_count = 0
        failed_count = 0

        all_findings: list[Finding] = []
        for r in self.results:
            all_findings.extend(r.findings)
            if r.status in ("CRITICAL", "EXPIRED", "ERROR"):
                failed_count += 1
            elif r.status == "WARNING":
                warning_count += 1
            else:
                passed_count += 1

        if self.ct_result:
            all_findings.extend(self.ct_result.findings)

        for f in all_findings:
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                critical_count += 1
            elif f.severity == FindingSeverity.WARNING:
                warning_count += 1

        self.summary = {
            "total_targets": len(self.results),
            "passed": passed_count,
            "warning": warning_count,
            "critical": critical_count,
            "failed": failed_count,
            "total_findings": len(all_findings),
        }

    def has_critical_findings(self) -> bool:
        """Check if any critical, high, or expired findings exist."""
        for r in self.results:
            if r.status in ("CRITICAL", "EXPIRED", "ERROR"):
                return True
            for f in r.findings:
                if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                    return True
        if self.ct_result:
            for f in self.ct_result.findings:
                if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
            "ct_result": self.ct_result.to_dict() if self.ct_result else None,
        }
