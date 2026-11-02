"""Tests for the node #115 hash-bucket projection model (0x5f099b0).

Run under plain python3 (pytest is not installed on this VM):

    python3 tests/test_hash_bucket_projection_115.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import hash_bucket_projection_115 as m

MASK64 = (1 << 64) - 1


def test_magic_is_inverse_of_seven():
    assert (m.MAGIC * 7) & MASK64 == 1
    assert m.ENTRY_BYTES == 56
    assert m.QWORDS_PER_ENTRY == 7


def test_scaled_count_is_entry_count_for_whole_spans():
    for entries in (0, 1, 2, 3, 10, 1000, 1 << 20):
        assert m.scaled_count(56 * entries) == entries


def test_scaled_count_literal_for_nonwhole_span():
    # No divisibility guard in-window: one extra qword past a whole
    # span scales literally, it does not round down to the entry
    # count. Callers must pass whole-entry spans.
    assert m.scaled_count(64) == (m.MAGIC + 1) & MASK64
    assert m.scaled_count(56 * 5 + 8) != 5


def test_empty_table_projects_to_base():
    assert m.bucket_index(0xDEADBEEF, 0) == 0
    assert m.entry_address(0x100000, 0xDEADBEEF, 0) == 0x100000


def test_bucket_bounds_and_edges():
    for entries in (1, 2, 7, 1000):
        span = 56 * entries
        assert m.bucket_index(0, span) == 0
        assert m.bucket_index(MASK64, span) == entries - 1
        for h in (1, 12345, 1 << 63, MASK64 - 1):
            assert 0 <= m.bucket_index(h, span) < entries


def test_entry_address_stride():
    base = 0x500000
    for entries in (10, 1000):
        span = 56 * entries
        seen = set()
        for h in range(0, 1 << 64, (1 << 64) // 97):
            addr = m.entry_address(base, h, span)
            assert (addr - base) % 56 == 0
            assert base <= addr < base + 56 * entries
            seen.add(addr)
        assert len(seen) > 1


def test_limb_transcription_matches_closed_form():
    rng = random.Random(115099)
    pairs = [(0, 0), (MASK64, MASK64), (1, 1), (MASK64, 1), (1, MASK64)]
    pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(200)]
    for h, scaled in pairs:
        assert m.limb_high_product(h, scaled) == ((h * scaled) & ((1 << 128) - 1)) >> 64


def test_project_end_to_end_with_stub_hash():
    def stub_hash(key):
        # A fixed stand-in for callee 0x61c38a0: not the real hash,
        # only a deterministic input to the projection.
        total = 0
        for byte in key:
            total = (total * 31 + byte) & MASK64
        return total

    base, entries = 0x800000, 1000
    span = 56 * entries
    addr = m.project(base, base + span, b"hello", stub_hash)
    h = stub_hash(b"hello")
    assert addr == base + 56 * (((h * entries) & ((1 << 128) - 1)) >> 64)
    # Same key, same table -> same entry; different key may differ.
    assert m.project(base, base + span, b"hello", stub_hash) == addr
    assert base <= addr < base + span


def test_project_uses_host_span_not_assumed_count():
    # Doubling the span doubles the entry count the projection
    # divides over: the window reads the span, never a count field.
    def const_hash(_key):
        return MASK64

    base = 0x1000
    assert m.project(base, base + 5600, b"k", const_hash) == base + 56 * 99
    assert m.project(base, base + 11200, b"k", const_hash) == base + 56 * 199


def test_packet_records_match_model():
    root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(
        root, "research/work-items/RE-001-hash-bucket-projection-115",
        "records.json")
    records = json.load(open(path))
    assert records["window"]["start"] == "0x5f099b0"
    assert records["window"]["end"] == "0x5f09a42"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["scale"]["magic"] == hex(m.MAGIC)
    assert records["scale"]["entry_bytes"] == m.ENTRY_BYTES
    assert records["hash_call"]["target"] == "0x61c38a0"
    assert records["census"]["direct_calls"] == [
        "0x5f0c460", "0x5f0c712", "0x5f0c74c", "0x5f0cad8",
        "0x5f0cb12", "0x5f0f6bd", "0x5f0fbdf"]


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
