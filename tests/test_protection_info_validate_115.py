"""Tests for tools/protection_info_validate_115.py (node #115 0x5f09b10).

The hash callee 0x61c3530's body is cited by contract only, so tests
use a recording stub hash and solve for the protection qword that
makes a record valid; flipping that qword must then fail. Run under
plain python3 (pytest is not installed on this VM):

    python3 tests/test_protection_info_validate_115.py
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import protection_info_validate_115 as m

MASK = (1 << 64) - 1


def stub_hash_factory():
    calls = []

    def stub(data, seed):
        calls.append((bytes(data), seed))
        # A deterministic stand-in, never claimed to be the real hash.
        return (seed ^ len(data) ^ sum(data)) & MASK

    return stub, calls


def build_record(key_payload, value_payload, tag, stub, capacity=0):
    """Build a structurally valid record, solving for protection_qword."""
    key_len = len(key_payload) + 8
    trailer = (tag & 0xFF) | (0x11223344556677 << 8)
    buf = bytearray()
    buf += bytes([key_len]) + key_payload
    buf += struct.pack("<Q", trailer)
    buf += bytes([len(value_payload)]) + value_payload
    shifted = struct.pack("<Q", trailer >> 8)
    fold = (
        stub(shifted, m.SEED_SHIFTED_TRAILER)
        ^ stub(key_payload, m.SEED_KEY)
        ^ stub(value_payload, m.SEED_VALUE)
    )
    protection = fold ^ stub(bytes([tag]), m.SEED_TAG_BYTE)
    return bytes(buf), protection


def test_valid_record_passes_and_clears_status():
    stub, _ = stub_hash_factory()
    buf, protection = build_record(b"KEYDATA!", b"VALUE!", 0x5A, stub)
    ok, err = m.validate(buf, 0, protection, stub)
    assert ok and err is None, (ok, err)
    status = bytearray(b"\xAB" * 16)
    m.clear_status(status)
    assert status[0:6] == b"\x00" * 6
    assert status[8:16] == b"\x00" * 8
    assert status[6:8] == b"\xAB\xAB", "bytes 6..7 are never written"


def test_key_parse_failure():
    stub, _ = stub_hash_factory()
    assert m.validate(b"", 0, 0, stub) == (False, m.MSG_KEY_PARSE)


def test_key_too_short():
    stub, _ = stub_hash_factory()
    # key_len 8 (empty payload + trailer) with capacity 1: 8 < 1 + 8.
    buf = bytes([8]) + struct.pack("<Q", 0) + bytes([0])
    assert m.validate(buf, 1, 0, stub) == (False, m.MSG_KEY_SHORT)


def test_key_too_long():
    stub, _ = stub_hash_factory()
    # key_len 20 claims more than the buffer holds after the prefix.
    buf = bytes([20]) + b"short"
    assert m.validate(buf, 0, 0, stub) == (False, m.MSG_KEY_LONG)


def test_key_len_at_remaining_boundary_then_value_parse_fails():
    stub, _ = stub_hash_factory()
    # key_len exactly equals the remaining bytes, so the value prefix
    # sits at the end of the buffer and its varint parse fails.
    buf = bytes([10]) + b"AB" + struct.pack("<Q", 0)
    assert m.validate(buf, 0, 0, stub) == (False, m.MSG_VALUE_PARSE)


def test_value_parse_failure():
    stub, _ = stub_hash_factory()
    # Key section ends exactly at the buffer end: no value prefix.
    buf = bytes([9]) + b"A" + struct.pack("<Q", 0)
    assert m.validate(buf, 0, 0, stub) == (False, m.MSG_VALUE_PARSE)


def test_value_too_short_and_too_long():
    stub, _ = stub_hash_factory()
    buf, protection = build_record(b"KEYDATA!", b"VALUE!", 0x5A, stub)
    # Rebuild manually: value prefix says 5, buffer holds 6 value bytes.
    key_section = buf[:1 + 8 + 8]
    long_buf = key_section + bytes([5]) + b"VALUE!"
    assert m.validate(long_buf, 0, protection, stub) == (
        False, m.MSG_VALUE_SHORT)
    short_buf = key_section + bytes([7]) + b"VALUE!"
    assert m.validate(short_buf, 0, protection, stub) == (
        False, m.MSG_VALUE_LONG)


def test_protection_mismatch():
    stub, _ = stub_hash_factory()
    buf, protection = build_record(b"KEYDATA!", b"VALUE!", 0x5A, stub)
    ok, err = m.validate(buf, 0, protection ^ 1, stub)
    assert (ok, err) == (False, m.MSG_PROTECTION)


def test_fold_call_order_and_seeds():
    stub, calls = stub_hash_factory()
    buf, protection = build_record(b"KEYDATA!", b"VALUE!", 0x5A, stub)
    calls.clear()
    ok, _ = m.validate(buf, 0, protection, stub)
    assert ok
    assert len(calls) == 4
    assert calls[0][1] == m.SEED_SHIFTED_TRAILER and len(calls[0][0]) == 8
    assert calls[1] == (b"KEYDATA!", m.SEED_KEY)
    assert calls[2] == (b"VALUE!", m.SEED_VALUE)
    assert calls[3] == (bytes([0x5A]), m.SEED_TAG_BYTE)


def test_varint_key_length():
    stub, _ = stub_hash_factory()
    # key_len 300 via two-byte LEB128: payload 292 bytes + trailer.
    # (build_record cannot emit a 300-byte single-byte prefix, so the
    # protection qword is solved directly from the components.)
    key_payload = bytes(range(256)) + bytes(36)
    assert len(key_payload) == 292
    tag = 0x01
    trailer = tag | (0x11223344556677 << 8)
    shifted = struct.pack("<Q", trailer >> 8)
    protection = (
        stub(shifted, m.SEED_SHIFTED_TRAILER)
        ^ stub(key_payload, m.SEED_KEY)
        ^ stub(b"V", m.SEED_VALUE)
        ^ stub(bytes([tag]), m.SEED_TAG_BYTE)
    )
    varint = bytes([0xAC, 0x02])  # 300 in unsigned LEB128
    buf2 = varint + key_payload + struct.pack("<Q", trailer)
    buf2 += bytes([1]) + b"V"
    ok, err = m.validate(buf2, 0, protection, stub)
    assert ok and err is None, (ok, err)


def test_key_len_capacity_boundary():
    stub, _ = stub_hash_factory()
    # key_len == capacity + 8 exactly must pass the short check.
    buf, protection = build_record(b"KEYDATA!", b"V", 0x01, stub)
    ok, err = m.validate(buf, 8, protection, stub)
    assert ok and err is None, (ok, err)


def test_packet_records_match_model():
    root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(
        root, "research/work-items/RE-001-protection-info-validate-115",
        "records.json")
    records = json.load(open(path))
    assert records["window"]["start"] == "0x5f09b10"
    assert records["window"]["end"] == "0x5f09e84"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["protection_fold"]["seeds"]["shifted_trailer"] == hex(
        m.SEED_SHIFTED_TRAILER)
    assert records["protection_fold"]["seeds"]["value"] == hex(m.SEED_VALUE)
    assert records["protection_fold"]["seeds"]["tag_byte"] == hex(
        m.SEED_TAG_BYTE)


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed += 1
            print("FAIL %s: %r" % (test.__name__, exc))
        else:
            print("ok %s" % test.__name__)
    print("%d passed, %d failed" % (len(TESTS) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
