# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        src.lh_ssl_tracker.asn1
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Clean-room ASN.1 DER parser for X.509 certificates and cryptographic parameters.

Provides zero-dependency decoding of ASN.1 Tag-Length-Value structures,
Object Identifiers (OIDs), timestamps, distinguished names, and public keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

# ASN.1 Universal Class Tags
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_TELETEX_STRING = 0x14
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

# Known Cryptographic and X.509 OIDs
KNOWN_OIDS: dict[str, str] = {
    # Signature Algorithms
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    # Public Key Algorithms
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10040.4.1": "dsa",
    # Named Elliptic Curves
    "1.2.840.10045.3.1.7": "secp256r1 (P-256)",
    "1.3.132.0.34": "secp384r1 (P-384)",
    "1.3.132.0.35": "secp521r1 (P-521)",
    "1.2.840.10045.3.1.1": "secp192r1 (P-192)",
    "1.3.132.0.1": "secp160r1 (P-160)",
    # Distinguished Name Attributes
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    # X.509 Extensions
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.37": "extKeyUsage",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
}

# Curve Bit Length Mapping
CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,
    "1.3.132.0.34": 384,
    "1.3.132.0.35": 521,
    "1.2.840.10045.3.1.1": 192,
    "1.3.132.0.1": 160,
    "1.3.101.112": 256,
    "1.3.101.113": 448,
}


@dataclass
class ASN1Node:
    """Represents a decoded ASN.1 Tag-Length-Value (TLV) element.

    Attributes:
        tag: The raw tag byte.
        data: The raw value bytes.
        children: Child nodes if constructed.
    """

    tag: int
    data: bytes
    children: list[ASN1Node] = field(default_factory=list)

    @property
    def is_constructed(self) -> bool:
        """Return True if node tag has constructed bit set (0x20)."""
        return bool(self.tag & 0x20)

    @property
    def tag_number(self) -> int:
        """Return the tag number masked against tag classes."""
        return self.tag & 0x1F


def parse_der(data: bytes, offset: int = 0, length: int | None = None) -> list[ASN1Node]:
    """Parse ASN.1 DER encoded bytes into a list of ASN1Node structures.

    Args:
        data: Raw DER encoded byte buffer.
        offset: Initial starting position in buffer.
        length: Maximum length to parse, or None for entire buffer.

    Returns:
        List of decoded top-level ASN1Node objects in this scope.

    Raises:
        ValueError: If DER encoding length or structure is malformed.
    """
    nodes: list[ASN1Node] = []
    end = len(data) if length is None else min(len(data), offset + length)

    while offset < end:
        tag = data[offset]
        offset += 1
        if offset >= end and tag != 0x00:
            raise ValueError(f"Truncated DER data at offset {offset}")

        # Length decoding
        length_byte = data[offset]
        offset += 1

        if (length_byte & 0x80) == 0:
            item_len = length_byte
        else:
            num_octets = length_byte & 0x7F
            if num_octets == 0 or num_octets > 4 or offset + num_octets > end:
                raise ValueError(f"Invalid ASN.1 length octets count: {num_octets}")
            item_len = int.from_bytes(data[offset : offset + num_octets], "big")
            offset += num_octets

        if offset + item_len > end:
            raise ValueError(
                f"ASN.1 item length {item_len} exceeds remaining buffer size {end - offset}"
            )

        val_bytes = data[offset : offset + item_len]
        offset += item_len

        # If constructed (bit 0x20 set), recursively parse children
        is_constructed = bool(tag & 0x20)
        children: list[ASN1Node] = []
        if is_constructed and item_len > 0:
            try:
                children = parse_der(val_bytes)
            except Exception:
                children = []

        nodes.append(ASN1Node(tag=tag, data=val_bytes, children=children))

    return nodes


def decode_oid(data: bytes) -> str:
    """Decode an ASN.1 Object Identifier from its DER value bytes.

    Args:
        data: Raw content octets of an ASN.1 OID tag.

    Returns:
        Dotted-decimal OID string (e.g., '1.2.840.113549.1.1.11').
    """
    if not data:
        return ""
    first_byte = data[0]
    parts: list[str] = [str(first_byte // 40), str(first_byte % 40)]

    val = 0
    for byte in data[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(val))
            val = 0

    return ".".join(parts)


def oid_to_name(oid: str) -> str:
    """Resolve an OID to its human-readable name or return the OID string.

    Args:
        oid: Dotted OID string.

    Returns:
        Known friendly name or fallback to raw OID.
    """
    return KNOWN_OIDS.get(oid, oid)


def decode_integer(data: bytes) -> int:
    """Decode an ASN.1 INTEGER value from DER octets.

    Args:
        data: Raw content bytes representing a signed big-endian integer.

    Returns:
        Decoded Python integer.
    """
    if not data:
        return 0
    return int.from_bytes(data, byteorder="big", signed=True)


def decode_bit_string(data: bytes) -> tuple[int, bytes]:
    """Decode an ASN.1 BIT STRING value.

    Args:
        data: Raw content bytes of BIT STRING (first byte is unused bits count).

    Returns:
        Tuple of (unused_bits, raw_payload_bytes).
    """
    if not data:
        return 0, b""
    unused_bits = data[0]
    payload = data[1:]
    return unused_bits, payload


def decode_string(data: bytes, tag: int) -> str:
    """Decode string values from ASN.1 string types.

    Args:
        data: Raw content bytes.
        tag: ASN.1 tag identifier.

    Returns:
        Decoded string.
    """
    if tag == TAG_UTF8_STRING:
        return data.decode("utf-8", errors="replace")
    elif tag == TAG_PRINTABLE_STRING or tag == TAG_IA5_STRING:
        return data.decode("ascii", errors="replace")
    elif tag == TAG_TELETEX_STRING:
        return data.decode("latin-1", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def decode_time(data: bytes, tag: int) -> datetime:
    """Parse UTCTime or GeneralizedTime into a timezone-aware UTC datetime.

    Args:
        data: Raw time bytes.
        tag: TAG_UTC_TIME (0x17) or TAG_GENERALIZED_TIME (0x18).

    Returns:
        Aware datetime in UTC timezone.

    Raises:
        ValueError: If time format cannot be parsed.
    """
    raw_str = data.decode("ascii", errors="replace").strip()

    if tag == TAG_UTC_TIME:
        # Format: YYMMDDHHMMSSZ or YYMMDDHHMMZ
        m = re.match(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$", raw_str)
        if not m:
            raise ValueError(f"Unrecognized UTCTime format: {raw_str}")
        year = int(m.group(1))
        # RFC 5280: If YY >= 50, year is 19YY, else 20YY
        year = 1900 + year if year >= 50 else 2000 + year
        month = int(m.group(2))
        day = int(m.group(3))
        hour = int(m.group(4))
        minute = int(m.group(5))
        second = int(m.group(6)) if m.group(6) else 0
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)

    elif tag == TAG_GENERALIZED_TIME:
        # Format: YYYYMMDDHHMMSS[.fff]Z
        m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$", raw_str)
        if not m:
            raise ValueError(f"Unrecognized GeneralizedTime format: {raw_str}")
        year = int(m.group(1))
        month = int(m.group(2))
        day = int(m.group(3))
        hour = int(m.group(4))
        minute = int(m.group(5))
        second = int(m.group(6))
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)

    raise ValueError(f"Unsupported time tag: {tag}")
