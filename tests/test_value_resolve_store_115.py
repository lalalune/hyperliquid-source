"""Tests for the node #115 value resolve-and-store model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_value_resolve_store_115.py

The hash callee (0x61c3530) is cited by contract in the packet, so
the tests inject a stub hash and pin the fold structure, the call
order, the seeds and the width truncation, not the hash itself.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from value_resolve_store_115 import (  # noqa: E402
    SEED_BYTE, SEED_FIRST, SEED_QWORD, SEED_SECOND,
    resolve_and_store)


def fresh_out():
    return bytearray(b"\xaa" * 16)


def test_direct_width_8_stores_full_qword():
    out = fresh_out()
    stored, value = resolve_and_store(8, out, value=0x1122334455667788)
    assert stored and value == 0x1122334455667788
    assert out[:8] == bytes.fromhex("8877665544332211")
    assert out[8:] == b"\xaa" * 8


def test_direct_width_4_stores_low_dword_only():
    out = fresh_out()
    stored, value = resolve_and_store(4, out, value=0x1122334455667788)
    assert stored and value == 0x1122334455667788
    assert out[:4] == bytes.fromhex("88776655")
    assert out[4:] == b"\xaa" * 12


def test_direct_width_2_stores_low_word_only():
    out = fresh_out()
    stored, _ = resolve_and_store(2, out, value=0x1122334455667788)
    assert stored
    assert out[:2] == bytes.fromhex("8877")
    assert out[2:] == b"\xaa" * 14


def test_direct_width_1_stores_low_byte_only():
    out = fresh_out()
    stored, _ = resolve_and_store(1, out, value=0x1122334455667788)
    assert stored
    assert out[:1] == b"\x88"
    assert out[1:] == b"\xaa" * 15


def test_direct_width_0_stores_nothing():
    out = fresh_out()
    stored, value = resolve_and_store(0, out, value=0x1122334455667788)
    assert not stored and value is None
    assert out == b"\xaa" * 16


def test_direct_unsupported_widths_store_nothing():
    for width in (3, 5, 6, 7, 9, 16, 0xFFFFFFFF):
        out = fresh_out()
        stored, value = resolve_and_store(width, out,
                                          value=0x1122334455667788)
        assert not stored, width
        assert value == 0x1122334455667788, width
        assert out == b"\xaa" * 16, width


def stub_hash_factory(results):
    calls = []

    def stub(data, seed):
        calls.append((data, seed))
        return results[len(calls) - 1]

    return stub, calls


def test_hash_fold_order_seeds_and_inputs():
    stub, calls = stub_hash_factory([0x1111, 0x2222, 0x3333, 0x4444])
    out = fresh_out()
    recorded = []
    stored, value = resolve_and_store(
        8, out, value=None, first=b"AB", second=b"CDEF",
        byte_input=0x5A, qword_input=0x0102030405060708,
        hash_fn=stub, calls=recorded)
    assert stored and value == (0x1111 ^ 0x2222 ^ 0x3333 ^ 0x4444)
    assert recorded == [
        (b"AB", SEED_FIRST),
        (b"CDEF", SEED_SECOND),
        (b"\x5a", SEED_BYTE),
        ((0x0102030405060708).to_bytes(8, "little"), SEED_QWORD),
    ]
    assert calls == recorded
    assert out[:8] == (0x1111 ^ 0x2222 ^ 0x3333 ^ 0x4444).to_bytes(8, "little")


def test_hash_fold_truncates_by_width():
    stub, _ = stub_hash_factory([0xFF, 0xF0, 0x0F, 0x100])
    out = fresh_out()
    stored, value = resolve_and_store(
        2, out, value=None, first=b"", second=b"",
        byte_input=0, qword_input=0, hash_fn=stub)
    # 0xFF ^ 0xF0 ^ 0x0F ^ 0x100 = 0x100
    assert stored and value == 0x100
    assert out[:2] == bytes.fromhex("0001")
    assert out[2:] == b"\xaa" * 14


def test_hash_path_width_0_makes_no_hash_call():
    calls = []

    def stub(data, seed):
        calls.append((data, seed))
        return 0xDEAD

    out = fresh_out()
    stored, value = resolve_and_store(
        0, out, value=None, first=b"AB", second=b"CD",
        byte_input=1, qword_input=2, hash_fn=stub)
    assert not stored and value is None
    assert calls == []
    assert out == b"\xaa" * 16


def test_hash_path_unsupported_width_still_folds_but_stores_nothing():
    stub, _ = stub_hash_factory([1, 2, 4, 8])
    out = fresh_out()
    stored, value = resolve_and_store(
        3, out, value=None, first=b"X", second=b"Y",
        byte_input=3, qword_input=4, hash_fn=stub)
    assert not stored and value == (1 ^ 2 ^ 4 ^ 8)
    assert out == b"\xaa" * 16


def test_byte_input_masked_to_one_byte():
    stub, _ = stub_hash_factory([0, 0, 0, 0])
    recorded = []
    resolve_and_store(8, fresh_out(), value=None, first=b"", second=b"",
                      byte_input=0x15A, qword_input=0,
                      hash_fn=stub, calls=recorded)
    assert recorded[2][0] == b"\x5a"


def test_qword_input_masked_to_64_bits():
    stub, _ = stub_hash_factory([0, 0, 0, 0])
    recorded = []
    resolve_and_store(8, fresh_out(), value=None, first=b"", second=b"",
                      byte_input=0, qword_input=1 << 70,
                      hash_fn=stub, calls=recorded)
    assert recorded[3][0] == (0).to_bytes(8, "little")


def test_packet_checks():
    here = os.path.dirname(__file__)
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-value-resolve-store-115", "records.json")
    records = json.load(open(packet))
    assert records["window"]["start"] == "0x5f09e90"
    assert records["window"]["end"] == "0x5f09faf"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["census"]["direct_calls"] == [
        "0x5f0ea4f", "0x5f0f7f0", "0x5f0f879", "0x5f0fe15", "0x5f10096"]
    sites = [c["site"] for c in records["in_window_calls"]]
    assert "0x5f09f3f" in sites  # first hash call
    assert "0x5f09f9a" in sites  # fourth hash call
    assert records["hash_fold"]["calls"][1]["seed"] == "0xd28aad72f49bd50b"


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
