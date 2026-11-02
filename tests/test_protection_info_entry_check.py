"""Tests for the node #94 ProtectionInfo entry check model (RE-001).

pytest-style test functions; pytest is not installed on this VM, so
the __main__ runner below executes them under plain python3.
The hash function is a stub (FNV-1a over data, seeded): the target
hash 0x5422f00 is used by contract, so the tests pin the model's
gates, layout and XOR combination, not the target hash's outputs.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from protection_info_entry_check import (  # noqa: E402
    SEQ_SEED,
    TYPE_SEED,
    USER_SEED,
    VALUE_SEED,
    build_buffer,
    check_entry,
    encode_prefix,
)

MASK = (1 << 64) - 1


def stub_hash(data, seed):
    h = seed & MASK
    for byte in data:
        h ^= byte
        h = (h * 0x100000001B3) & MASK
    return h


def expected_for(user_key, value_type, sequence, value):
    return (
        stub_hash(sequence.to_bytes(8, "little"), SEQ_SEED)
        ^ stub_hash(user_key, USER_SEED)
        ^ stub_hash(value, VALUE_SEED)
        ^ stub_hash(bytes([value_type]), TYPE_SEED)
    )


def test_happy_path_single_byte_prefixes():
    buf = build_buffer(b"user-key-1", 5, 123456, b"val-bytes")
    res = check_entry(buf, expected_for(b"user-key-1", 5, 123456, b"val-bytes"), 0, stub_hash)
    assert res["ok"] is True
    assert res["user_key"] == b"user-key-1"
    assert res["value_type"] == 5
    assert res["sequence"] == 123456
    assert res["value"] == b"val-bytes"


def test_happy_path_two_byte_varint_length():
    user = b"u" * 120  # entry length 128 -> varint 0x80 0x01
    buf = build_buffer(user, 2, 7, b"v")
    assert buf[0] == 0x80 and buf[1] == 0x01
    res = check_entry(buf, expected_for(user, 2, 7, b"v"), 0, stub_hash)
    assert res["ok"] is True
    assert res["user_key"] == user


def test_empty_buffer_length_parse_failure():
    res = check_entry(b"", 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Unable to parse internal key length"}


def test_truncated_varint_length_parse_failure():
    # 0x80 with no terminator before the end.
    res = check_entry(b"\x80", 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Unable to parse internal key length"}


def test_fifth_continuation_byte_fails():
    # Five continuation bytes: the helper's shift passes 28 and fails.
    res = check_entry(b"\x80\x80\x80\x80\x80\x01", 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Unable to parse internal key length"}


def test_minimum_length_gate_and_boundary():
    buf = build_buffer(b"key", 1, 9, b"v")
    # Entry length is 11; min_gate 4 demands >= 12.
    res = check_entry(buf, 0, 4, stub_hash)
    assert res == {"ok": False, "detail": "Internal key length too short"}
    # Boundary: min_gate 3 demands >= 11, which the entry meets.
    res = check_entry(buf, expected_for(b"key", 1, 9, b"v"), 3, stub_hash)
    assert res["ok"] is True


def test_length_beyond_remaining():
    buf = build_buffer(b"key", 1, 9, b"v")
    # Claim an entry length of 40 while only 11 entry bytes follow.
    doctored = encode_prefix(40) + buf[1:]
    res = check_entry(doctored, 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Internal key length too long"}


def test_value_parse_failure():
    buf = build_buffer(b"key", 1, 9, b"v")
    # Truncate after the entry: the value prefix starts at the end.
    entry_len = 3 + 8
    truncated = buf[:1 + entry_len] + b"\x80"
    res = check_entry(truncated, 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Unable to parse value length"}


def test_value_too_short_trailing_bytes():
    buf = build_buffer(b"key", 1, 9, b"v") + b"extra"
    res = check_entry(buf, 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Value length too short"}


def test_value_too_long():
    buf = build_buffer(b"key", 1, 9, b"v")
    # Rewrite the value length prefix to claim more than remains.
    entry_len = 3 + 8
    head = buf[:1 + entry_len]
    doctored = head + encode_prefix(9) + b"v"
    res = check_entry(doctored, 0, 0, stub_hash)
    assert res == {"ok": False, "detail": "Value length too long"}


def test_mismatch_on_wrong_expected():
    buf = build_buffer(b"key", 1, 9, b"v")
    res = check_entry(buf, expected_for(b"key", 1, 9, b"v") ^ 1, 0, stub_hash)
    assert res == {"ok": False, "detail": "ProtectionInfo mismatch"}


def test_corruption_control_flipped_value_byte():
    buf = bytearray(build_buffer(b"key", 1, 9, b"v"))
    buf[-1] ^= 0xFF  # flip a value byte, keep the original expected hash
    res = check_entry(bytes(buf), expected_for(b"key", 1, 9, b"v"), 0, stub_hash)
    assert res == {"ok": False, "detail": "ProtectionInfo mismatch"}


def test_type_and_sequence_change_the_hash():
    buf = build_buffer(b"key", 1, 9, b"v")
    # The hash for a different type must not match this buffer.
    res = check_entry(buf, expected_for(b"key", 2, 9, b"v"), 0, stub_hash)
    assert res == {"ok": False, "detail": "ProtectionInfo mismatch"}
    res = check_entry(buf, expected_for(b"key", 1, 10, b"v"), 0, stub_hash)
    assert res == {"ok": False, "detail": "ProtectionInfo mismatch"}


def test_packet_records_match_window_and_census():
    path = os.path.join(
        os.path.dirname(__file__), "..", "research", "work-items",
        "RE-001-protection-info-entry-check-94", "records.json")
    records = json.load(open(path))
    assert records["window"]["start"] == "0x51694e0"
    assert records["window"]["end"] == "0x5169854"
    assert records["window"]["size_bytes"] == 884
    assert records["census"]["direct_calls"] == ["0x516e449", "0x516f1e8", "0x516f805"]
    assert len(records["strings"]) == 7


def main():
    names = sorted(n for n in globals() if n.startswith("test_"))
    for name in names:
        globals()[name]()
        print("pass", name)
    print("%d tests passed" % len(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
