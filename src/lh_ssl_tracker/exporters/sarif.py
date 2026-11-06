# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        src.lh_ssl_tracker.exporters.sarif
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 format exporter for security findings.

Generates standard SARIF reports compatible with GitHub Code Scanning,
security dashboards, and CI/CD pipelines.
"""

from __future__ import annotations

import json
from typing import Any

from lh_ssl_tracker.models import AuditReport, Finding, FindingSeverity

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

RULE_METADATA: dict[str, dict[str, Any]] = {
    "SSL-EXP-001": {
        "name": "CertificateExpired",
        "shortDescription": {"text": "TLS certificate has expired."},
        "fullDescription": {
            "text": (
                "The TLS/SSL certificate is past its validity expiration date, "
                "causing service disruption."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-EXP-002": {
        "name": "CriticalExpirationImminent",
        "shortDescription": {"text": "TLS certificate expires within critical threshold."},
        "fullDescription": {
            "text": "The certificate is approaching expiration within the critical SLA threshold."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-EXP-003": {
        "name": "UpcomingCertificateExpiration",
        "shortDescription": {"text": "TLS certificate expires within warning threshold."},
        "fullDescription": {
            "text": "The certificate is approaching its expiration date and should be renewed."
        },
        "defaultConfiguration": {"level": "warning"},
    },
    "SSL-EXP-004": {
        "name": "CertificateNotYetValid",
        "shortDescription": {"text": "TLS certificate validity start is in the future."},
        "fullDescription": {
            "text": "The certificate NotBefore timestamp has not yet been reached."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-CRYPTO-001": {
        "name": "InsecureSignatureAlgorithmMD5",
        "shortDescription": {"text": "Certificate uses insecure MD5 signature algorithm."},
        "fullDescription": {
            "text": "MD5 hash algorithm is vulnerable to collision attacks and must not be used."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-CRYPTO-002": {
        "name": "DeprecatedSignatureAlgorithmSHA1",
        "shortDescription": {"text": "Certificate uses deprecated SHA-1 signature algorithm."},
        "fullDescription": {
            "text": (
                "SHA-1 hash algorithm has been cryptographically deprecated and must be upgraded."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-CRYPTO-003": {
        "name": "InsufficientRSAKeyLength",
        "shortDescription": {"text": "RSA key length is below the 2048-bit minimum."},
        "fullDescription": {
            "text": (
                "RSA public keys shorter than 2048 bits provide inadequate cryptographic strength."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-CRYPTO-004": {
        "name": "InsufficientECCKeyLength",
        "shortDescription": {"text": "Elliptic Curve key length is below the 224-bit minimum."},
        "fullDescription": {
            "text": "EC keys shorter than 224 bits provide insufficient security margins."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-HOST-001": {
        "name": "HostnameSANMismatch",
        "shortDescription": {"text": "Target hostname does not match Common Name or SANs."},
        "fullDescription": {
            "text": (
                "The hostname requested does not match the certificate "
                "Subject CN or SAN extensions."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "SSL-TRUST-001": {
        "name": "SelfSignedCertificate",
        "shortDescription": {"text": "Certificate is self-signed."},
        "fullDescription": {
            "text": (
                "Self-signed certificates are untrusted by default operating system trust stores."
            )
        },
        "defaultConfiguration": {"level": "warning"},
    },
    "CT-ROGUE-001": {
        "name": "RogueShadowSubdomainDetected",
        "shortDescription": {"text": "Unauthorized shadow subdomain detected in CT logs."},
        "fullDescription": {
            "text": (
                "A publicly logged certificate exists for an unapproved subdomain "
                "not in the asset inventory."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "CT-UNEXPECTED-CA-001": {
        "name": "UnexpectedCertificateAuthority",
        "shortDescription": {
            "text": "Certificate issued by unexpected Certificate Authority in CT logs."
        },
        "fullDescription": {
            "text": (
                "A public certificate was issued by an unauthorized or untrusted "
                "Certificate Authority."
            )
        },
        "defaultConfiguration": {"level": "warning"},
    },
}


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to SARIF level (error, warning, note)."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "error"
    elif severity == FindingSeverity.WARNING:
        return "warning"
    return "note"


def export_sarif(report: AuditReport, indent: int = 2) -> str:
    """Generate OASIS SARIF v2.1.0 document from an AuditReport.

    Args:
        report: AuditReport to convert.
        indent: Indentation spaces for the JSON output.

    Returns:
        SARIF v2.1.0 JSON string.
    """
    all_findings: list[Finding] = []
    for r in report.results:
        all_findings.extend(r.findings)
    if report.ct_result:
        all_findings.extend(report.ct_result.findings)

    # Collect unique rules used
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in all_findings:
        rule_id = finding.rule_id
        if rule_id not in rules_dict:
            meta = RULE_METADATA.get(
                rule_id,
                {
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.message},
                    "defaultConfiguration": {"level": _severity_to_sarif_level(finding.severity)},
                },
            )
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": meta["name"],
                "shortDescription": meta["shortDescription"],
                "fullDescription": meta["fullDescription"],
                "defaultConfiguration": meta["defaultConfiguration"],
            }

        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _severity_to_sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.target or "unknown_target",
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
                "properties": finding.details,
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-ssl-tracker",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-ssl-tracker",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)
