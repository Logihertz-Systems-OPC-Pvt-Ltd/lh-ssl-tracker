# lh-ssl-tracker

[![CI](https://github.com/logihertz/lh-ssl-tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/logihertz/lh-ssl-tracker/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise Certificate Transparency (CT) log monitor and TLS/SSL certificate expiration tracker developed by **Logihertz Systems OPC Pvt Ltd**.

`lh-ssl-tracker` audits internal and external infrastructure for upcoming certificate expirations, SLA policy violations, deprecated cryptographic parameters, and unauthorized public subdomain issuances.

---

## Key Features

- **Live Endpoint Auditing**: Connect to remote TLS services (`host:port`) using Server Name Indication (SNI) to evaluate live peer certificates without disrupting connections.
- **Local Bundle Auditing**: Inspect local X.509 PEM certificate bundles, trust stores, and intermediate chains in bulk.
- **SLA & Expiration Tracking**: Configurable warning (`--warn-days`) and critical (`--crit-days`) thresholds to preempt outages and ensure SLA compliance.
- **Cryptographic Strength Analyzer**:
  - Flags insecure and deprecated signature hashing algorithms (MD5, SHA-1).
  - Flags insufficient public key bit lengths (RSA < 2048-bit, ECC < 224-bit).
  - Detects self-signed certificates and untrusted CA issuers.
- **Hostname & SAN Verification**: Validates target hostnames against Subject Common Names (CN) and Subject Alternative Names (SANs) according to RFC 6125 wildcard matching rules.
- **Certificate Transparency (CT) Monitoring**: Ingests public CT log feeds (crt.sh JSON schema or local snapshots) and compares issued certificates against approved asset allowlists to detect rogue certificates, shadow subdomains, and unauthorized CAs.
- **Zero-Dependency Cryptography**: Built with a clean-room ASN.1 DER parser written in pure Python 3.11+ standard library, eliminating external C-binding vulnerabilities and platform build issues.
- **Multi-Format Reporting**:
  - **Terminal Tables**: Colored tables, badges, and audit summary panels powered by `rich`.
  - **Structured JSON**: Machine-readable output for SIEM, CMDB, and log ingestion.
  - **OASIS SARIF v2.1.0**: Native format for GitHub Code Scanning and security dashboards.

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/logihertz/lh-ssl-tracker.git
cd lh-ssl-tracker

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entry point is `lh-ssl`.

```
Usage: lh-ssl [OPTIONS] COMMAND [ARGS]...

Commands:
  check         Inspect live TLS endpoints for expiration, cryptographic strength, and SAN mismatches.
  monitor-ct    Analyze Certificate Transparency log JSON feeds to detect shadow subdomains and rogue CAs.
  audit-bundle  Audit local PEM certificate bundles for expiration, weak cryptographic parameters, and policies.
```

### 1. Endpoint Checking (`lh-ssl check`)

Inspect a single host, custom port, or a bulk inventory file.

```bash
# Check a single TLS endpoint with custom SLA thresholds
lh-ssl check api.example.com:443 --warn-days 30 --crit-days 7

# Inspect bulk inventory list from file
lh-ssl check targets.txt --format table

# Export findings to OASIS SARIF format for CI/CD
lh-ssl check targets.txt --format sarif --output results.sarif
```

#### Target Inventory Format (`targets.txt`)

```text
# Production edge endpoints
app.example.com:443
api.example.com:443

# Internal services
internal.vpn.example.com:8443
192.168.1.50:443
```

---

### 2. Certificate Transparency Monitoring (`lh-ssl monitor-ct`)

Monitor public CT logs for a domain against an approved subdomain allowlist.

```bash
lh-ssl monitor-ct example.com \
  --ct-feed ct_feed.json \
  --allowlist subdomains.txt \
  --format table
```

#### Allowlist Format (`subdomains.txt`)

```text
# Approved production domains
example.com
www.example.com
api.example.com

# Wildcard patterns supported
*.internal.example.com
*.staging.example.com
```

#### Sample CT Log JSON (`ct_feed.json` from crt.sh)

```json
[
  {
    "id": 12345678,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "api.example.com",
    "name_value": "api.example.com\nwww.example.com",
    "not_before": "2026-01-01T00:00:00",
    "not_after": "2026-04-01T00:00:00"
  },
  {
    "id": 12345679,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "shadow-test.example.com",
    "name_value": "shadow-test.example.com",
    "not_before": "2026-01-01T00:00:00",
    "not_after": "2026-04-01T00:00:00"
  }
]
```

---

### 3. PEM Bundle Auditing (`lh-ssl audit-bundle`)

Audit local certificate files, trust bundles, and CA certificate packages.

```bash
# Audit certificate bundle
lh-ssl audit-bundle /etc/ssl/certs/bundle.pem --warn-days 30

# Export structured JSON report
lh-ssl audit-bundle /etc/ssl/certs/bundle.pem --format json --output audit-report.json
```

---

## Security Rules Reference

| Rule ID | Name | Severity | Description |
|:---|:---|:---|:---|
| `SSL-EXP-001` | CertificateExpired | `CRITICAL` | Certificate validity date has expired. |
| `SSL-EXP-002` | CriticalExpirationImminent | `CRITICAL` | Certificate expires within critical SLA threshold (`<= crit-days`). |
| `SSL-EXP-003` | UpcomingCertificateExpiration | `WARNING` | Certificate expires within warning threshold (`<= warn-days`). |
| `SSL-EXP-004` | CertificateNotYetValid | `CRITICAL` | Certificate NotBefore timestamp is in the future. |
| `SSL-CRYPTO-001` | InsecureSignatureAlgorithmMD5 | `CRITICAL` | MD5 or MD2 signature hash algorithm detected. |
| `SSL-CRYPTO-002` | DeprecatedSignatureAlgorithmSHA1 | `HIGH` | Deprecated SHA-1 signature algorithm detected. |
| `SSL-CRYPTO-003` | InsufficientRSAKeyLength | `HIGH` | RSA key length is shorter than the 2048-bit enterprise minimum. |
| `SSL-CRYPTO-004` | InsufficientECCKeyLength | `HIGH` | Elliptic Curve key length is shorter than the 224-bit minimum. |
| `SSL-HOST-001` | HostnameSANMismatch | `HIGH` | Requested hostname does not match Common Name or SANs (RFC 6125). |
| `SSL-TRUST-001` | SelfSignedCertificate | `WARNING` | Self-signed certificate (untrusted by standard public PKI). |
| `CT-ROGUE-001` | RogueShadowSubdomainDetected | `HIGH` | Domain in CT logs is not present in approved asset allowlist. |
| `CT-UNEXPECTED-CA-001` | UnexpectedCertificateAuthority | `WARNING` | Certificate issued by an unauthorized Certificate Authority. |
| `SSL-CONN-001` | TLSConnectionFailure | `CRITICAL` | Network timeout, DNS failure, or TLS handshake refusal. |

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All certificates compliant; no critical or high severity findings. |
| `1` | One or more `CRITICAL` or `HIGH` severity issues detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed JSON). |

---

## Development & Testing

```bash
# Run unit tests with code coverage
uv run pytest --cov=lh_ssl_tracker --cov-report=term-missing

# Run code style and lint checks
uv run ruff check .

# Run static application security testing (SAST)
uv run bandit -r src/
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Developed with precision by **Logihertz Systems OPC Pvt Ltd**.
