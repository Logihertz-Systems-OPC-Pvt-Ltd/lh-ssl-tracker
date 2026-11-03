"""Cryptographic strength and expiration analyzer for TLS certificates.

Evaluates expiration windows against warning and critical thresholds,
checks for deprecated or weak signature hashes and key bit lengths,
verifies hostname against SANs/CN, and flags policy deviations.
"""

from __future__ import annotations

from datetime import UTC, datetime

from lh_ssl_tracker.models import (
    CertificateAuditResult,
    Finding,
    FindingCategory,
    FindingSeverity,
    ParsedCertificate,
)


def matches_hostname(hostname: str, pattern: str) -> bool:
    """Verify if a target hostname matches a certificate domain pattern (including wildcards).

    Follows RFC 6125: Wildcard labels only match a single DNS label.

    Args:
        hostname: The target domain or host to test (e.g., 'api.example.com').
        pattern: The certificate pattern (e.g., '*.example.com' or 'example.com').

    Returns:
        True if the hostname matches the pattern, False otherwise.
    """
    host = hostname.strip().lower().rstrip(".")
    pat = pattern.strip().lower().rstrip(".")

    if host == pat:
        return True

    # Wildcard handling: *.domain.com
    if pat.startswith("*."):
        suffix = pat[2:]
        # Host must end with .suffix and have exactly one label before it
        if host.endswith("." + suffix):
            prefix = host[: -(len(suffix) + 1)]
            if "." not in prefix and prefix:
                return True

    return False


class CertificateAnalyzer:
    """Security and compliance analyzer for X.509 certificates."""

    def __init__(
        self,
        warn_days: int = 30,
        crit_days: int = 7,
        min_rsa_bits: int = 2048,
        min_ec_bits: int = 224,
    ) -> None:
        """Initialize the analyzer with policy thresholds.

        Args:
            warn_days: Warning threshold in days prior to certificate expiration.
            crit_days: Critical threshold in days prior to certificate expiration.
            min_rsa_bits: Minimum allowed RSA public key bit length.
            min_ec_bits: Minimum allowed EC public key bit length.
        """
        self.warn_days = warn_days
        self.crit_days = crit_days
        self.min_rsa_bits = min_rsa_bits
        self.min_ec_bits = min_ec_bits

    def analyze(
        self,
        cert: ParsedCertificate,
        target: str = "",
        target_hostname: str | None = None,
        now: datetime | None = None,
    ) -> CertificateAuditResult:
        """Analyze a parsed certificate and produce an audit result with findings.

        Args:
            cert: The ParsedCertificate instance to evaluate.
            target: The display target label or file identifier.
            target_hostname: Network hostname to verify against SANs/CN (optional).
            now: Current timestamp (defaults to datetime.now(timezone.utc)).

        Returns:
            CertificateAuditResult with status and security findings.
        """
        if now is None:
            now = datetime.now(UTC)

        findings: list[Finding] = []
        target_label = target or cert.common_name or cert.fingerprint_sha256[:16]

        # 1. Expiration & Validity Window Analysis
        delta = cert.not_after - now
        days_remaining = delta.total_seconds() / 86400.0

        status = "OK"

        if days_remaining < 0:
            status = "EXPIRED"
            days_ago = abs(int(days_remaining))
            findings.append(
                Finding(
                    rule_id="SSL-EXP-001",
                    title="Certificate Expired",
                    category=FindingCategory.EXPIRATION,
                    severity=FindingSeverity.CRITICAL,
                    target=target_label,
                    message=(
                        f"Certificate expired {days_ago} day(s) ago on "
                        f"{cert.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                    ),
                    details={
                        "days_remaining": round(days_remaining, 1),
                        "not_after": cert.not_after.isoformat(),
                    },
                )
            )
        elif days_remaining <= self.crit_days:
            status = "CRITICAL"
            days_left = max(0, int(days_remaining))
            findings.append(
                Finding(
                    rule_id="SSL-EXP-002",
                    title="Critical Expiration Imminent",
                    category=FindingCategory.EXPIRATION,
                    severity=FindingSeverity.CRITICAL,
                    target=target_label,
                    message=(
                        f"Certificate expires in {days_left} day(s) on "
                        f"{cert.not_after.strftime('%Y-%m-%d')} "
                        f"(Critical threshold <= {self.crit_days}d)."
                    ),
                    details={
                        "days_remaining": round(days_remaining, 1),
                        "crit_threshold_days": self.crit_days,
                    },
                )
            )
        elif days_remaining <= self.warn_days:
            status = "WARNING"
            days_left = int(days_remaining)
            findings.append(
                Finding(
                    rule_id="SSL-EXP-003",
                    title="Upcoming Certificate Expiration",
                    category=FindingCategory.EXPIRATION,
                    severity=FindingSeverity.WARNING,
                    target=target_label,
                    message=(
                        f"Certificate expires in {days_left} day(s) on "
                        f"{cert.not_after.strftime('%Y-%m-%d')} "
                        f"(Warning threshold <= {self.warn_days}d)."
                    ),
                    details={
                        "days_remaining": round(days_remaining, 1),
                        "warn_threshold_days": self.warn_days,
                    },
                )
            )

        # Check NotBefore validity
        if now < cert.not_before:
            status = "CRITICAL"
            findings.append(
                Finding(
                    rule_id="SSL-EXP-004",
                    title="Certificate Not Yet Valid",
                    category=FindingCategory.EXPIRATION,
                    severity=FindingSeverity.CRITICAL,
                    target=target_label,
                    message=(
                        f"Certificate is not valid until "
                        f"{cert.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                    ),
                    details={"not_before": cert.not_before.isoformat()},
                )
            )

        # 2. Cryptographic Strength: Signature Algorithm
        sig_name_lower = cert.signature_algorithm_name.lower()
        if "md5" in sig_name_lower or cert.signature_algorithm_oid == "1.2.840.113549.1.1.4":
            findings.append(
                Finding(
                    rule_id="SSL-CRYPTO-001",
                    title="Insecure Signature Algorithm (MD5)",
                    category=FindingCategory.CRYPTO_STRENGTH,
                    severity=FindingSeverity.CRITICAL,
                    target=target_label,
                    message=(
                        f"Certificate uses insecure signature algorithm "
                        f"'{cert.signature_algorithm_name}'. "
                        "MD5 is vulnerable to collision attacks and forbidden in production."
                    ),
                    details={
                        "algorithm": cert.signature_algorithm_name,
                        "oid": cert.signature_algorithm_oid,
                    },
                )
            )
        elif "sha1" in sig_name_lower or cert.signature_algorithm_oid in (
            "1.2.840.113549.1.1.5",
            "1.2.840.10040.4.3",
            "1.2.840.10045.4.1",
        ):
            findings.append(
                Finding(
                    rule_id="SSL-CRYPTO-002",
                    title="Deprecated Signature Algorithm (SHA-1)",
                    category=FindingCategory.CRYPTO_STRENGTH,
                    severity=FindingSeverity.HIGH,
                    target=target_label,
                    message=(
                        f"Certificate uses deprecated signature algorithm "
                        f"'{cert.signature_algorithm_name}'. "
                        "SHA-1 has been cryptographically broken. Migrate to SHA-256 or SHA-384."
                    ),
                    details={
                        "algorithm": cert.signature_algorithm_name,
                        "oid": cert.signature_algorithm_oid,
                    },
                )
            )

        # 3. Cryptographic Strength: Key Length
        if cert.public_key_type == "RSA":
            if 0 < cert.public_key_bits < self.min_rsa_bits:
                findings.append(
                    Finding(
                        rule_id="SSL-CRYPTO-003",
                        title="Insufficient RSA Key Length",
                        category=FindingCategory.CRYPTO_STRENGTH,
                        severity=FindingSeverity.HIGH,
                        target=target_label,
                        message=(
                            f"RSA key length of {cert.public_key_bits} bits is below "
                            f"the enterprise minimum of {self.min_rsa_bits} bits."
                        ),
                        details={
                            "key_type": "RSA",
                            "key_bits": cert.public_key_bits,
                            "min_required_bits": self.min_rsa_bits,
                        },
                    )
                )
        elif cert.public_key_type == "EC":
            if 0 < cert.public_key_bits < self.min_ec_bits:
                findings.append(
                    Finding(
                        rule_id="SSL-CRYPTO-004",
                        title="Insufficient ECC Key Length",
                        category=FindingCategory.CRYPTO_STRENGTH,
                        severity=FindingSeverity.HIGH,
                        target=target_label,
                        message=(
                            f"Elliptic curve key length of {cert.public_key_bits} bits is below "
                            f"minimum of {self.min_ec_bits} bits."
                        ),
                        details={
                            "key_type": "EC",
                            "key_bits": cert.public_key_bits,
                            "min_required_bits": self.min_ec_bits,
                        },
                    )
                )

        # 4. Hostname / SAN Mismatch Verification
        check_host = target_hostname
        if check_host:
            # Extract clean hostname from target (strip port if present)
            host_clean = check_host.split(":")[0].strip()
            # If target looks like a domain name or IP (not a file path)
            if "/" not in host_clean and "\\" not in host_clean and " " not in host_clean:
                candidate_domains: list[str] = []
                if cert.common_name:
                    candidate_domains.append(cert.common_name)
                candidate_domains.extend(cert.subject_alt_names)

                matched = any(
                    matches_hostname(host_clean, pattern) for pattern in candidate_domains
                )

                if candidate_domains and not matched:
                    findings.append(
                        Finding(
                            rule_id="SSL-HOST-001",
                            title="Hostname / SAN Mismatch",
                            category=FindingCategory.HOSTNAME_MISMATCH,
                            severity=FindingSeverity.HIGH,
                            target=target_label,
                            message=(
                                f"Target hostname '{host_clean}' does not match certificate "
                                f"Common Name ('{cert.common_name}') or Subject Alternative Names "
                                f"({', '.join(cert.subject_alt_names) or 'none'})."
                            ),
                            details={
                                "target_hostname": host_clean,
                                "common_name": cert.common_name,
                                "sans": cert.subject_alt_names,
                            },
                        )
                    )

        # 5. Self-Signed Certificate
        if cert.is_self_signed and not cert.is_ca:
            findings.append(
                Finding(
                    rule_id="SSL-TRUST-001",
                    title="Self-Signed Certificate",
                    category=FindingCategory.POLICY,
                    severity=FindingSeverity.WARNING,
                    target=target_label,
                    message=(
                        f"Certificate is self-signed (Issuer '{cert.issuer_common_name}' matches "
                        f"Subject '{cert.common_name}'). Not trusted by default public PKI."
                    ),
                    details={
                        "common_name": cert.common_name,
                        "issuer": cert.issuer_common_name,
                    },
                )
            )

        # Elevate status if any critical/high finding is present
        has_critical = any(
            f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for f in findings
        )
        if has_critical and status not in ("CRITICAL", "EXPIRED"):
            status = "CRITICAL"

        return CertificateAuditResult(
            target=target_label,
            certificate=cert,
            days_remaining=days_remaining,
            status=status,
            findings=findings,
        )
