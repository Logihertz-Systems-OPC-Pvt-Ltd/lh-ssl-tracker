# Security Policy

## Overview

Security is a primary pillar of `lh-ssl-tracker`. We take the security of enterprise infrastructure, certificate analysis, and data integrity seriously. This document outlines our vulnerability disclosure policy and security guidelines.

---

## Supported Versions

Only the latest release of `lh-ssl-tracker` receives active security updates and vulnerability patches.

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability or weakness in `lh-ssl-tracker`, please follow responsible disclosure principles. **Do not create a public GitHub issue for security vulnerabilities.**

### Disclosure Process

1. **Email Notification**: Send a detailed report to `security@logihertz.com` with the subject line `[SECURITY] lh-ssl-tracker: <Brief Description>`.
2. **Details to Include**:
   - Component affected (e.g. ASN.1 parser, scanner, CT monitor, exporters).
   - Description of the vulnerability and its potential security impact.
   - Minimal reproducible proof-of-concept (PoC) or sample input (e.g., malformed PEM, malicious CT feed).
   - Any remediation suggestions or pull requests you have prepared.
3. **Response Timeline**:
   - **Acknowledgment**: Within 48 hours of initial receipt.
   - **Assessment & Triage**: Within 5 business days.
   - **Patch & Advisory Release**: Coordinated with the reporter before public disclosure.

---

## Cryptographic Security Practices

`lh-ssl-tracker` enforces strict cryptographic hygiene:
- **Clean-Room Architecture**: Zero untrusted C-extensions for ASN.1 decoding.
- **Safe Socket Handling**: Connections to untrusted endpoints default to non-blocking timeouts to prevent resource exhaustion or DoS.
- **Input Validation**: Strict bounds checking on ASN.1 DER length descriptors to prevent buffer overflows or unbounded memory allocation.
- **Safe Output Serialization**: Automated schema validation and sanitization for JSON and OASIS SARIF v2.1.0 output streams.

