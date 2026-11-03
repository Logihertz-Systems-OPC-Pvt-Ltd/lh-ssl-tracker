"""Unit tests for ASN.1 DER parser and OID resolution."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from lh_ssl_tracker.asn1 import (
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_SEQUENCE,
    TAG_UTC_TIME,
    decode_bit_string,
    decode_integer,
    decode_oid,
    decode_string,
    decode_time,
    oid_to_name,
    parse_der,
)


def test_decode_integer() -> None:
    """Test integer decoding for positive, negative, and zero."""
    assert decode_integer(b"\x00") == 0
    assert decode_integer(b"\x7f") == 127
    assert decode_integer(b"\x00\x80") == 128
    assert decode_integer(b"\x01\x00") == 256
    assert decode_integer(b"\xff") == -1
    assert decode_integer(b"") == 0


def test_decode_oid() -> None:
    """Test OID decoding from raw DER octets."""
    # 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    raw = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])
    assert decode_oid(raw) == "1.2.840.113549.1.1.11"
    assert decode_oid(b"") == ""

    # Known name resolution
    assert oid_to_name("1.2.840.113549.1.1.11") == "sha256WithRSAEncryption"
    assert oid_to_name("1.2.840.113549.1.1.4") == "md5WithRSAEncryption"
    assert oid_to_name("9.9.9.9") == "9.9.9.9"


def test_decode_bit_string() -> None:
    """Test BIT STRING unpacking."""
    raw = b"\x00\x01\x02\x03"
    unused, payload = decode_bit_string(raw)
    assert unused == 0
    assert payload == b"\x01\x02\x03"
    assert decode_bit_string(b"") == (0, b"")


def test_decode_string_encodings() -> None:
    """Test various string tag decodings."""
    assert decode_string(b"example.com", 0x13) == "example.com"
    assert decode_string("üñîçødé".encode(), 0x0C) == "üñîçødé"
    assert decode_string(b"test string", 0x16) == "test string"


def test_decode_time_utc_and_generalized() -> None:
    """Test UTCTime and GeneralizedTime parsing."""
    # UTCTime: 261104120000Z -> 2026-11-04 12:00:00 UTC
    utc_raw = b"261104120000Z"
    t1 = decode_time(utc_raw, TAG_UTC_TIME)
    assert t1 == datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)

    # UTCTime with year >= 50: 991231235959Z -> 1999-12-31 23:59:59 UTC
    utc_old = b"991231235959Z"
    t_old = decode_time(utc_old, TAG_UTC_TIME)
    assert t_old == datetime(1999, 12, 31, 23, 59, 59, tzinfo=UTC)

    # GeneralizedTime: 20300101153000Z -> 2030-01-01 15:30:00 UTC
    gen_raw = b"20300101153000Z"
    t2 = decode_time(gen_raw, TAG_GENERALIZED_TIME)
    assert t2 == datetime(2030, 1, 1, 15, 30, 0, tzinfo=UTC)

    with pytest.raises(ValueError):
        decode_time(b"invalid-date", TAG_UTC_TIME)

    with pytest.raises(ValueError):
        decode_time(b"invalid-date", TAG_GENERALIZED_TIME)

    with pytest.raises(ValueError):
        decode_time(b"2026", 0x99)


def test_parse_der_structure() -> None:
    """Test recursive TLV parsing."""
    # Construct a simple SEQUENCE: [INTEGER 42, UTF8String 'hello']
    int_node = bytes([TAG_INTEGER, 0x01, 42])
    str_val = b"hello"
    str_node = bytes([0x0C, len(str_val)]) + str_val
    seq_data = int_node + str_node
    der = bytes([TAG_SEQUENCE, len(seq_data)]) + seq_data

    nodes = parse_der(der)
    assert len(nodes) == 1
    assert nodes[0].tag == TAG_SEQUENCE
    assert nodes[0].is_constructed
    assert len(nodes[0].children) == 2
    assert nodes[0].children[0].tag == TAG_INTEGER
    assert decode_integer(nodes[0].children[0].data) == 42


def test_parse_der_errors() -> None:
    """Test malformed DER input handling."""
    with pytest.raises(ValueError, match="Truncated DER data"):
        parse_der(b"\x30")

    # Length exceeds buffer
    with pytest.raises(ValueError, match="exceeds remaining buffer"):
        parse_der(b"\x30\x10\x00")

    # Invalid length octets count
    with pytest.raises(ValueError, match="Invalid ASN.1 length"):
        parse_der(b"\x30\x85\x01\x02\x03\x04\x05")
