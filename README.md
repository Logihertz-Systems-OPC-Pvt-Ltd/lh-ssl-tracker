# lh-ssl-tracker

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-ssl-tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-ssl-tracker/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise tls/ssl certificate & ct log monitor developed by **Logihertz Systems (OPC) Private Limited**.

Audits live TLS endpoints, local X.509 PEM certificate bundles, and Certificate Transparency (crt.sh) feeds for imminent SLA expirations, weak RSA/ECC keys, SHA-1/MD5 signatures, SAN mismatches, and rogue shadow subdomains.

---

## Key Features

- **Live Endpoint Auditing**: Connects to remote TLS services using Server Name Indication (SNI) to evaluate peer certificates non-disruptively.
- **Local Bundle Auditing**: Inspects local X.509 PEM certificate bundles, trust stores, and intermediate chains in bulk.
- **SLA Expiration Tracking**: Configurable warning (`--warn-days`) and critical (`--crit-days`) thresholds to preempt service outages.
- **Cryptographic Strength Analyzer**: Flags weak signature hashes (MD5, SHA-1), short RSA keys (< 2048-bit), and self-signed certificates.
- **Certificate Transparency (CT) Monitoring**: Ingests public CT log feeds and compares issued certs against approved subdomain allowlists.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `SSL-EXP-001` | `CRITICAL` | Certificate validity date has expired |
| `SSL-EXP-002` | `CRITICAL` | Certificate expires within critical SLA threshold (<= crit-days) |
| `SSL-EXP-003` | `WARNING` | Certificate expires within warning SLA threshold (<= warn-days) |
| `SSL-EXP-004` | `CRITICAL` | Certificate NotBefore timestamp is in the future |
| `SSL-CRYPTO-001` | `CRITICAL` | Insecure signature hash algorithm detected (MD5 or MD2) |
| `SSL-CRYPTO-002` | `HIGH` | Deprecated SHA-1 signature algorithm detected |
| `SSL-CRYPTO-003` | `HIGH` | RSA key length is shorter than 2048-bit enterprise minimum |
| `SSL-CRYPTO-004` | `HIGH` | Elliptic Curve key length is shorter than 224-bit minimum |
| `SSL-HOST-001` | `HIGH` | Requested hostname does not match Common Name or SANs (RFC 6125) |
| `CT-ROGUE-001` | `HIGH` | Domain in Certificate Transparency log is not in asset allowlist |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-ssl-tracker.git
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

The primary executable entrypoint is `lh-ssl` (also accessible via `lh-ssl`).

```bash
# Check a live TLS endpoint with SLA thresholds
lh-ssl check api.example.com:443 --warn-days 30 --crit-days 7

# Monitor public CT logs against an approved allowlist
lh-ssl monitor-ct example.com --ct-feed ct_feed.json --allowlist subdomains.txt

# Audit a local PEM certificate bundle
lh-ssl audit-bundle /etc/ssl/certs/bundle.pem --format json

# Export findings to OASIS SARIF v2.1.0
lh-ssl check targets.txt --format sarif --output ssl-findings.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
