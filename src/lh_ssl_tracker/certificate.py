# ==============================================================================
# Product:       lh-ssl-tracker (lh-ssl)
# Module:        src.lh_ssl_tracker.certificate
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""X.509 Certificate parsing and attribute extraction.

Processes PEM and DER format certificates, extracting cryptographic parameters,
validity windows, distinguished names, public key bit lengths, and SAN extensions.
"""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime

from lh_ssl_tracker.asn1 import (
    CURVE_BITS,
    TAG_BOOLEAN,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_SET,
    ASN1Node,
    decode_bit_string,
    decode_integer,
    decode_oid,
    decode_string,
    decode_time,
    oid_to_name,
    parse_der,
)
from lh_ssl_tracker.models import ParsedCertificate

PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
    re.MULTILINE,
)


def extract_pem_blocks(pem_content: str) -> list[bytes]:
    """Extract raw DER byte blocks from a PEM-encoded string or certificate bundle.

    Args:
        pem_content: Content containing one or more PEM certificates.

    Returns:
        List of raw DER byte arrays for each certificate found.
    """
    blocks: list[bytes] = []
    for match in PEM_CERT_PATTERN.finditer(pem_content):
        b64_str = "".join(match.group(1).split())
        if b64_str:
            try:
                blocks.append(base64.b64decode(b64_str))
            except (ValueError, TypeError) as exc:
                _ = exc
    return blocks


def _parse_name_attributes(name_node: ASN1Node) -> dict[str, str]:
    """Extract RDN attribute key-value pairs from a Name SEQUENCE.

    Args:
        name_node: ASN1Node representing a Name sequence of RDN sets.

    Returns:
        Dictionary mapping attribute labels (e.g., 'CN', 'O', 'C') to string values.
    """
    attributes: dict[str, str] = {}
    for rdn_set in name_node.children:
        if rdn_set.tag != TAG_SET and not rdn_set.is_constructed:
            continue
        for attr_seq in rdn_set.children:
            if not attr_seq.children or len(attr_seq.children) < 2:
                continue
            oid_node = attr_seq.children[0]
            val_node = attr_seq.children[1]
            if oid_node.tag == TAG_OID:
                oid_str = decode_oid(oid_node.data)
                attr_name = oid_to_name(oid_str)
                str_val = decode_string(val_node.data, val_node.tag)
                attributes[attr_name] = str_val
    return attributes


def _parse_validity(validity_node: ASN1Node) -> tuple[datetime, datetime]:
    """Parse notBefore and notAfter timestamps from Validity SEQUENCE.

    Args:
        validity_node: ASN1Node containing Validity elements.

    Returns:
        Tuple of (not_before, not_after) timezone-aware datetimes.
    """
    if len(validity_node.children) < 2:
        raise ValueError("Malformed Validity SEQUENCE in certificate")

    nb_node = validity_node.children[0]
    na_node = validity_node.children[1]

    not_before = decode_time(nb_node.data, nb_node.tag)
    not_after = decode_time(na_node.data, na_node.tag)

    return not_before, not_after


def _parse_spki(spki_node: ASN1Node) -> tuple[str, int]:
    """Extract public key algorithm name and bit length from SubjectPublicKeyInfo.

    Args:
        spki_node: ASN1Node representing SubjectPublicKeyInfo.

    Returns:
        Tuple of (public_key_type, bit_length).
    """
    if len(spki_node.children) < 2:
        return "Unknown", 0

    alg_id_node = spki_node.children[0]
    bit_string_node = spki_node.children[1]

    if not alg_id_node.children:
        return "Unknown", 0

    key_alg_oid = decode_oid(alg_id_node.children[0].data)
    _, pub_bytes = decode_bit_string(bit_string_node.data)

    # RSA Encryption
    if key_alg_oid == "1.2.840.113549.1.1.1":
        try:
            rsa_nodes = parse_der(pub_bytes)
            if rsa_nodes and rsa_nodes[0].children:
                modulus_node = rsa_nodes[0].children[0]
                if modulus_node.tag == TAG_INTEGER:
                    modulus = decode_integer(modulus_node.data)
                    return "RSA", modulus.bit_length()
        except Exception:
            return "RSA", 0
        return "RSA", 0

    # Elliptic Curve (id-ecPublicKey)
    if key_alg_oid == "1.2.840.10045.2.1":
        # Check curve OID if present in algorithm parameters
        if len(alg_id_node.children) > 1 and alg_id_node.children[1].tag == TAG_OID:
            curve_oid = decode_oid(alg_id_node.children[1].data)
            curve_bits = CURVE_BITS.get(curve_oid)
            if curve_bits:
                return "EC", curve_bits

        # Fallback to estimating from uncompressed point size (0x04 || X || Y)
        if len(pub_bytes) >= 65 and pub_bytes[0] == 0x04:
            coord_len = (len(pub_bytes) - 1) // 2
            return "EC", coord_len * 8

        return "EC", 256

    # Ed25519
    if key_alg_oid == "1.3.101.112":
        return "Ed25519", 256

    # Ed448
    if key_alg_oid == "1.3.101.113":
        return "Ed448", 448

    # DSA
    if key_alg_oid == "1.2.840.10040.4.1":
        if len(alg_id_node.children) > 1 and alg_id_node.children[1].children:
            p_node = alg_id_node.children[1].children[0]
            if p_node.tag == TAG_INTEGER:
                p_val = decode_integer(p_node.data)
                return "DSA", p_val.bit_length()
        return "DSA", 1024

    return oid_to_name(key_alg_oid), len(pub_bytes) * 8


def _parse_extensions(exts_node: ASN1Node) -> tuple[list[str], bool]:
    """Parse Subject Alternative Names (SANs) and basic constraints.

    Args:
        exts_node: ASN1Node representing Extensions sequence (tag [3] or SEQUENCE).

    Returns:
        Tuple of (sans_list, is_ca).
    """
    sans: list[str] = []
    is_ca = False

    # Check if outer node is context tag [3]
    seq_node = exts_node
    if (
        (exts_node.tag & 0x1F) == 3
        and exts_node.children
        and exts_node.children[0].tag == TAG_SEQUENCE
    ):
        seq_node = exts_node.children[0]

    for ext in seq_node.children:
        if not ext.children or len(ext.children) < 2:
            continue
        oid_node = ext.children[0]
        if oid_node.tag != TAG_OID:
            continue
        oid_str = decode_oid(oid_node.data)

        # Value is last child (OCTET STRING)
        val_node = ext.children[-1]
        if val_node.tag != TAG_OCTET_STRING:
            continue

        # Subject Alternative Name (SAN): 2.5.29.17
        if oid_str == "2.5.29.17":
            try:
                san_der = parse_der(val_node.data)
                if san_der and san_der[0].children:
                    for general_name in san_der[0].children:
                        tag_num = general_name.tag & 0x1F
                        # Tag 2: dNSName
                        if tag_num == 2:
                            sans.append(general_name.data.decode("ascii", errors="replace"))
                        # Tag 7: iPAddress
                        elif tag_num == 7:
                            if len(general_name.data) == 4:
                                sans.append(".".join(str(b) for b in general_name.data))
                            elif len(general_name.data) == 16:
                                parts = [
                                    f"{general_name.data[i]:02x}{general_name.data[i + 1]:02x}"
                                    for i in range(0, 16, 2)
                                ]
                                sans.append(":".join(parts))
            except (ValueError, IndexError) as exc:
                _ = exc

        # Basic Constraints: 2.5.29.19
        elif oid_str == "2.5.29.19":
            try:
                bc_der = parse_der(val_node.data)
                if bc_der and bc_der[0].children:
                    for bc_field in bc_der[0].children:
                        if bc_field.tag == TAG_BOOLEAN and bc_field.data:
                            is_ca = bool(bc_field.data[0] != 0)
            except (ValueError, IndexError) as exc:
                _ = exc

    return sans, is_ca


def parse_der_certificate(der_bytes: bytes, raw_pem: str = "") -> ParsedCertificate:
    """Parse a single DER-encoded X.509 certificate into a ParsedCertificate.

    Args:
        der_bytes: Raw DER bytes.
        raw_pem: Optional original PEM string representation.

    Returns:
        ParsedCertificate populated with extracted attributes and cryptographic metadata.

    Raises:
        ValueError: If DER structure is invalid or missing required X.509 elements.
    """
    root_nodes = parse_der(der_bytes)
    if not root_nodes or root_nodes[0].tag != TAG_SEQUENCE:
        raise ValueError("Invalid X.509 Certificate: Root is not a SEQUENCE")

    cert_sequence = root_nodes[0]
    if len(cert_sequence.children) < 3:
        raise ValueError("Invalid X.509 Certificate: Insufficient elements in top SEQUENCE")

    tbs_cert = cert_sequence.children[0]
    sig_alg_outer = cert_sequence.children[1]

    # Fingerprint
    fingerprint_sha256 = hashlib.sha256(der_bytes).hexdigest().upper()

    # Signature Algorithm
    sig_alg_oid = ""
    if sig_alg_outer.children and sig_alg_outer.children[0].tag == TAG_OID:
        sig_alg_oid = decode_oid(sig_alg_outer.children[0].data)
    sig_alg_name = oid_to_name(sig_alg_oid)

    # Process TBSCertificate elements
    tbs_children = tbs_cert.children
    idx = 0

    # Optional version [0] EXPLICIT
    if tbs_children and (tbs_children[idx].tag & 0x1F) == 0:
        idx += 1

    # Serial Number
    serial_hex = ""
    if idx < len(tbs_children) and tbs_children[idx].tag == TAG_INTEGER:
        serial_hex = tbs_children[idx].data.hex().upper()
        idx += 1

    # Inner signature algorithm identifier
    if idx < len(tbs_children) and tbs_children[idx].tag == TAG_SEQUENCE:
        idx += 1

    # Issuer Name
    issuer_dict: dict[str, str] = {}
    if idx < len(tbs_children):
        issuer_dict = _parse_name_attributes(tbs_children[idx])
        idx += 1

    # Validity
    not_before = None
    not_after = None
    if idx < len(tbs_children):
        not_before, not_after = _parse_validity(tbs_children[idx])
        idx += 1

    if not_before is None or not_after is None:
        raise ValueError("Missing Validity sequence in certificate")

    # Subject Name
    subject_dict: dict[str, str] = {}
    if idx < len(tbs_children):
        subject_dict = _parse_name_attributes(tbs_children[idx])
        idx += 1

    # SubjectPublicKeyInfo
    pk_type = "Unknown"
    pk_bits = 0
    if idx < len(tbs_children):
        pk_type, pk_bits = _parse_spki(tbs_children[idx])
        idx += 1

    # Extensions [3] EXPLICIT
    sans: list[str] = []
    is_ca = False
    while idx < len(tbs_children):
        node = tbs_children[idx]
        if (node.tag & 0x1F) == 3 or node.tag == TAG_SEQUENCE:
            parsed_sans, parsed_is_ca = _parse_extensions(node)
            sans.extend(parsed_sans)
            if parsed_is_ca:
                is_ca = True
        idx += 1

    cn = subject_dict.get("CN", "")
    issuer_cn = issuer_dict.get("CN", "")
    is_self_signed = (cn == issuer_cn and cn != "") or (
        subject_dict == issuer_dict and bool(subject_dict)
    )

    # If raw_pem wasn't provided, reconstruct standard PEM
    if not raw_pem:
        b64 = base64.b64encode(der_bytes).decode("ascii")
        chunks = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        raw_pem = (
            "-----BEGIN CERTIFICATE-----\n" + "\n".join(chunks) + "\n-----END CERTIFICATE-----\n"
        )

    return ParsedCertificate(
        fingerprint_sha256=fingerprint_sha256,
        serial_number=serial_hex,
        subject=subject_dict,
        issuer=issuer_dict,
        common_name=cn,
        issuer_common_name=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        signature_algorithm_oid=sig_alg_oid,
        signature_algorithm_name=sig_alg_name,
        public_key_type=pk_type,
        public_key_bits=pk_bits,
        subject_alt_names=sans,
        is_self_signed=is_self_signed,
        is_ca=is_ca,
        raw_pem=raw_pem,
        raw_der=der_bytes,
    )


def parse_pem_bundle(pem_content: str) -> list[ParsedCertificate]:
    """Parse all PEM certificates found in a certificate bundle or file string.

    Args:
        pem_content: String containing one or more PEM certificates.

    Returns:
        List of parsed certificates.
    """
    der_blocks = extract_pem_blocks(pem_content)
    certificates: list[ParsedCertificate] = []
    for der in der_blocks:
        try:
            cert = parse_der_certificate(der)
            certificates.append(cert)
        except (ValueError, IndexError) as exc:
            _ = exc
    return certificates
