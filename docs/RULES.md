# Security Rules Reference: lh-ssl-tracker

An enterprise certificate transparency & tls expiration tracker developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-ssl-tracker`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `SSL-EXP-001` | `CRITICAL` | Expiration | Certificate Validity Date Has Expired |
| `SSL-EXP-002` | `CRITICAL` | Expiration | Certificate Expires Within Critical SLA Threshold |
| `SSL-EXP-003` | `WARNING` | Expiration | Certificate Expires Within Warning SLA Threshold |
| `SSL-EXP-004` | `CRITICAL` | Validity | Certificate NotBefore Timestamp is in the Future |
| `SSL-CRYPTO-001` | `CRITICAL` | Cryptography | Insecure Signature Hash Algorithm Detected (MD5, MD2) |
| `SSL-CRYPTO-002` | `HIGH` | Cryptography | Deprecated SHA-1 Signature Algorithm Detected |
| `SSL-CRYPTO-003` | `HIGH` | Cryptography | Insufficient RSA Key Length (< 2048-bit) |
| `SSL-CRYPTO-004` | `HIGH` | Cryptography | Insufficient ECC Key Length (< 224-bit) |
| `SSL-HOST-001` | `HIGH` | Hostname Validation | Requested Hostname Does Not Match Common Name or SANs |
| `CT-ROGUE-001` | `HIGH` | Certificate Transparency | Rogue Domain in Certificate Transparency Log Not in Allowlist |

---

## Granular Rule Specifications

### `SSL-EXP-001`: Certificate Validity Date Has Expired

- **Severity**: `CRITICAL`
- **Category**: `Expiration`
- **Description**: Live or local TLS certificate validity date (notAfter) has passed.
- **Remediation**: Renew and deploy updated TLS certificate immediately.

---

### `SSL-EXP-002`: Certificate Expires Within Critical SLA Threshold

- **Severity**: `CRITICAL`
- **Category**: `Expiration`
- **Description**: Certificate expires within critical SLA threshold (<= crit-days, default 7 days).
- **Remediation**: Execute emergency certificate renewal to prevent imminent service outage.

---

### `SSL-EXP-003`: Certificate Expires Within Warning SLA Threshold

- **Severity**: `WARNING`
- **Category**: `Expiration`
- **Description**: Certificate expires within warning SLA threshold (<= warn-days, default 30 days).
- **Remediation**: Initiate routine automated certificate renewal pipeline.

---

### `SSL-EXP-004`: Certificate NotBefore Timestamp is in the Future

- **Severity**: `CRITICAL`
- **Category**: `Validity`
- **Description**: Certificate NotBefore timestamp is ahead of current system time.
- **Remediation**: Verify system clock synchronization via NTP and ensure certificate is active.

---

### `SSL-CRYPTO-001`: Insecure Signature Hash Algorithm Detected (MD5, MD2)

- **Severity**: `CRITICAL`
- **Category**: `Cryptography`
- **Description**: Certificate signed using cryptographically broken MD5 or MD2 hash algorithm.
- **Remediation**: Reissue certificate using SHA-256 or SHA-384 signature hash.

---

### `SSL-CRYPTO-002`: Deprecated SHA-1 Signature Algorithm Detected

- **Severity**: `HIGH`
- **Category**: `Cryptography`
- **Description**: Certificate signed using deprecated SHA-1 hash algorithm.
- **Remediation**: Reissue certificate using modern SHA-256 or SHA-384 algorithm.

---

### `SSL-CRYPTO-003`: Insufficient RSA Key Length (< 2048-bit)

- **Severity**: `HIGH`
- **Category**: `Cryptography`
- **Description**: RSA public key length is shorter than 2048-bit enterprise standard.
- **Remediation**: Generate new private key with at least 2048-bit (preferably 3072-bit) RSA modulus.

---

### `SSL-CRYPTO-004`: Insufficient ECC Key Length (< 224-bit)

- **Severity**: `HIGH`
- **Category**: `Cryptography`
- **Description**: Elliptic Curve public key is shorter than 224-bit minimum.
- **Remediation**: Reissue certificate using NIST P-256, P-384, or Curve25519 ECC curve.

---

### `SSL-HOST-001`: Requested Hostname Does Not Match Common Name or SANs

- **Severity**: `HIGH`
- **Category**: `Hostname Validation`
- **Description**: Target hostname not listed in Subject Common Name or Subject Alternative Names (RFC 6125).
- **Remediation**: Reissue certificate including all target hostnames in Subject Alternative Name (SAN) extension.

---

### `CT-ROGUE-001`: Rogue Domain in Certificate Transparency Log Not in Allowlist

- **Severity**: `HIGH`
- **Category**: `Certificate Transparency`
- **Description**: Certificate issued for domain not present in approved production asset allowlist.
- **Remediation**: Investigate unauthorized certificate issuance and revoke rogue certificate with issuing CA.

---
