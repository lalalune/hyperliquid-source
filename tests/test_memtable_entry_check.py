"""Tests for tools/memtable_entry_check.py (RE-001, node #94 0x5167040).

The binary's hash callee (0x5422f00) cannot be executed on this VM,
so dispatch tests inject a deterministic stub hash and construct the
stored checksum from the model's own chain: they prove the parse,
width dispatch and detail composition, not the hash constants.  The
default MurmurHash64A implementation is exercised only structurally
(determinism, input sensitivity, empty-input value).

Run with pytest when available; otherwise plain python3 runs the
__main__ block below (pytest is not installed on this VM).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memtable_entry_check import (  # noqa: E402
    FAILED_DETAIL,
    NO_LENGTH_DETAIL,
    NO_VALUE_DETAIL,
    SHORT_DETAIL,
    Record,
    check,
    decode_varint,
    hash_bytes,
    hex_encode,
)

MASK64 = (1 << 64) - 1


def stub_hash(data, seed):
    """Deterministic stand-in for std::_Hash_bytes for dispatch tests."""
    return (seed ^ (len(data) * 0x9E3779B97F4A7C15 + 0x12345)) & MASK64


def build_entry(user_key, value_type, seq, suffix, stored, width,
                varint_len=False):
    """Build a buffer: length prefix + user key + trailer + suffix + stored.

    The stored checksum is placed at suffix_start + len(suffix), as
    the binary reads it; the caller supplies its bytes.
    """
    trailer = bytes([value_type]) + seq.to_bytes(7, "little")
    entry = user_key + trailer
    buf = bytearray()
    if varint_len:
        n = len(entry)
        while True:
            byte = n & 0x7F
            n >>= 7
            if n:
                buf.append(byte | 0x80)
            else:
                buf.append(byte)
                break
    else:
        buf.append(len(entry))
    buf += entry
    if len(suffix) < 0x80:
        buf.append(len(suffix))
    else:
        n = len(suffix)
        while True:
            byte = n & 0x7F
            n >>= 7
            if n:
                buf.append(byte | 0x80)
            else:
                buf.append(byte)
                break
    buf += suffix
    buf += stored
    return bytes(buf)


def combined_for(user_key, value_type, seq, suffix, hash_fn):
    return (
        hash_fn(user_key, 0)
        ^ hash_fn(suffix, 0xD28AAD72F49BD50B)
        ^ hash_fn(bytes([value_type]), 0xA5155AE5E937AA16)
        ^ hash_fn(seq.to_bytes(8, "little"), 0x77A00858DDD37F21)
    )


def stored_bytes(combined, width):
    return (combined & ((1 << (8 * width)) - 1)).to_bytes(width, "little")


def test_width_zero_returns_zero_without_reading():
    assert check(b"", 0, 0) == Record(0, "")
    assert check(b"\x01\x02", 0, 1) == Record(0, "")


def test_single_byte_length_match():
    user_key = b"alpha"
    value_type, seq, suffix = 3, 12345, b"tag"
    combined = combined_for(user_key, value_type, seq, suffix, stub_hash)
    buf = build_entry(user_key, value_type, seq, suffix,
                      stored_bytes(combined, 2), 2)
    assert check(buf, 2, 0, stub_hash) == Record(0, "")


def test_varint_length_match():
    # 120 user-key bytes + 8 trailer bytes = 128, which forces the
    # two-byte varint form (0x80 0x01) instead of a single length byte.
    user_key = bytes(range(1, 121))
    value_type, seq, suffix = 1, 999, b""
    combined = combined_for(user_key, value_type, seq, suffix, stub_hash)
    buf = build_entry(user_key, value_type, seq, suffix,
                      stored_bytes(combined, 4), 4, varint_len=True)
    assert check(buf, 4, 1, stub_hash) == Record(0, "")


def test_each_check_width_matches_and_mismatches():
    user_key, value_type, seq, suffix = b"k", 7, 42, b"s"
    combined = combined_for(user_key, value_type, seq, suffix, stub_hash)
    for width in (1, 2, 4, 8):
        good = build_entry(user_key, value_type, seq, suffix,
                           stored_bytes(combined, width), width)
        assert check(good, width, 0, stub_hash) == Record(0, "")
        bad_stored = (combined ^ 1) & ((1 << (8 * width)) - 1)
        bad = build_entry(user_key, value_type, seq, suffix,
                          bad_stored.to_bytes(width, "little"), width)
        assert check(bad, width, 0, stub_hash) == Record(2, FAILED_DETAIL)


def test_non_check_widths_skip_comparison():
    user_key, value_type, seq, suffix = b"k", 7, 42, b"s"
    for width in (3, 5, 6, 7):
        buf = build_entry(user_key, value_type, seq, suffix, b"\x00" * width,
                          width)
        assert check(buf, width, 1, stub_hash) == Record(0, "")


def test_short_length_errors():
    assert check(b"\x07" + b"1234567", 2, 0) == Record(2, SHORT_DETAIL)
    assert check(b"\x00", 2, 0) == Record(2, SHORT_DETAIL)
    # Varint length 5 (0x85 0x00 decodes to 5) is also too short.
    assert check(b"\x85\x00" + b"12345", 2, 0) == Record(2, SHORT_DETAIL)


def test_unterminated_length_varint():
    assert check(b"\x80\x80\x80\x80\x80", 2, 0) == Record(2, NO_LENGTH_DETAIL)


def test_unterminated_suffix_varint():
    # Entry of 9 bytes (1 user-key byte + 8 trailer), then a suffix
    # length varint that never terminates within its 5-byte bound.
    buf = b"\x09" + b"u" + bytes([2]) + (7).to_bytes(7, "little")
    buf += b"\x80\x80\x80\x80\x80"
    assert check(buf, 2, 0, stub_hash) == Record(2, NO_VALUE_DETAIL)


def test_mismatch_plain_detail_when_flag_zero():
    user_key, value_type, seq, suffix = b"abc", 5, 77, b"zz"
    buf = build_entry(user_key, value_type, seq, suffix, b"\x00\x00", 2)
    assert check(buf, 2, 0, stub_hash) == Record(2, FAILED_DETAIL)


def test_mismatch_full_detail_when_flag_set():
    user_key, value_type, seq, suffix = b"abc", 5, 77, b"zz"
    buf = build_entry(user_key, value_type, seq, suffix, b"\x00\x00", 2)
    expected = (
        FAILED_DETAIL
        + "Unrecognized value type: 5. "
        + "User key: 616263. "
        + "seq: 77. "
    )
    assert check(buf, 2, 1, stub_hash) == Record(2, expected)


def test_trailer_split_type_and_seq():
    # The detail echoes the split: low trailer byte is the type, the
    # next 7 bytes little-endian are the sequence.
    user_key, suffix = b"q", b""
    value_type, seq = 0xAB, 0x01020304050607
    combined = combined_for(user_key, value_type, seq, suffix, stub_hash)
    bad_stored = bytes([(combined ^ 1) & 0xFF])
    buf = build_entry(user_key, value_type, seq, suffix, bad_stored, 1)
    record = check(buf, 1, 1, stub_hash)
    assert record.code == 2
    assert "Unrecognized value type: 171. " in record.detail
    assert "seq: 283686952306183. " in record.detail


def test_corruption_control_default_hash():
    # Flipping one user-key byte changes the chain, so a previously
    # matching stored checksum must now mismatch.
    user_key, value_type, seq, suffix = b"stable", 1, 9, b"t"
    combined = combined_for(user_key, value_type, seq, suffix, hash_bytes)
    buf = bytearray(build_entry(user_key, value_type, seq, suffix,
                                stored_bytes(combined, 4), 4))
    assert check(bytes(buf), 4, 0) == Record(0, "")
    buf[1] ^= 0x01
    assert check(bytes(buf), 4, 0).code == 2


def test_default_hash_structural():
    assert hash_bytes(b"", 0) == 0
    assert hash_bytes(b"abc", 7) == hash_bytes(b"abc", 7)
    assert hash_bytes(b"abc", 7) != hash_bytes(b"abd", 7)
    assert hash_bytes(b"abc", 7) != hash_bytes(b"abc", 8)


def test_hex_encode_lowercase():
    assert hex_encode(b"\x00\xff\xab\x10") == "00ffab10"


def test_decode_varint_bounds():
    assert decode_varint(b"\x05rest", 0, 5) == (5, 1)
    assert decode_varint(b"\xc8\x01", 0, 2) == (200, 2)
    assert decode_varint(b"\x80\x80", 0, 2) is None


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", name, ":", exc)
    print("%d tests, %d failed" % (len(tests), failed))
    sys.exit(1 if failed else 0)
