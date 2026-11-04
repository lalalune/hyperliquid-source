"""Tests for the node #115 memtable iterator seek gate model.

pytest-style file; pytest is not installed on this VM, so it runs
under plain python3 via the __main__ runner below.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from memtable_iterator_seek_gate_115 import (  # noqa: E402
    KNOWN_FN,
    chain_gate,
    chain_slice_lens,
    mask_bits,
    probe,
    probe_base,
    probe_len,
    ror12,
    seek_gate,
)

HERE = os.path.dirname(os.path.abspath(__file__))
PACKET = os.path.join(
    HERE, "..", "research", "work-items",
    "RE-014-memtable-iterator-seek-gate-115")
OTHER = 0x5F00000


def test_probe_len_and_chain_slices():
    assert probe_len(100, 12) == 80
    assert chain_slice_lens(80) == [80, 72, 64, 56]


def test_probe_base_and_mask():
    assert probe_base(7, 0x12345678) == (7 * 0x12345678) >> 32
    assert mask_bits(0xC0FFEE) == (0xC0FFEE & 63, (0xC0FFEE >> 6) & 63)
    assert ror12(0x1000) == 1
    h = 0xABCDEF1234567890
    assert ror12(h) == ((h >> 12) | ((h << 52) & ((1 << 64) - 1)))


def test_probe_round_zero_always():
    # rounds=0 still tests round 0: a word missing a mask bit misses.
    h32 = 0x12345678
    h = (h32 * 0x9E3779B97F4A7C13) & ((1 << 64) - 1)
    b0, b1 = mask_bits(h)
    words = {0: 0}
    assert probe(words, 0, 0, h32) is False
    words[0] = (1 << b0) | (1 << b1)
    assert probe(words, 0, 0, h32) is True


def test_probe_rotation_across_rounds():
    # Round 0 passes but round 1 fails only after the ror-12 rotation.
    h32 = 0x0BADF00D
    h0 = (h32 * 0x9E3779B97F4A7C13) & ((1 << 64) - 1)
    h1 = ror12(h0)
    b0, b1 = mask_bits(h0)
    c0, c1 = mask_bits(h1)
    words = {0: (1 << b0) | (1 << b1), 1: (1 << c0)}  # round 1 lacks c1
    assert probe(words, 0, 2, h32) is False
    words[1] = (1 << c0) | (1 << c1)
    assert probe(words, 0, 2, h32) is True


def test_chain_gate_known_skip_and_call():
    levels = [(KNOWN_FN, None), (KNOWN_FN, None),
              (KNOWN_FN, None), (OTHER, True)]
    assert chain_gate(levels) == "probe"
    levels = [(KNOWN_FN, None), (OTHER, False),
              (KNOWN_FN, None), (OTHER, True)]
    assert chain_gate(levels) == "inner"
    levels = [(OTHER, True), (KNOWN_FN, None),
              (KNOWN_FN, None), (OTHER, True)]
    assert chain_gate(levels) == "probe"


def test_seek_gate_null_table_and_predicate_false():
    out = seek_gate(None, 0, 100, [], {}, 0, 0, 0, 0, 0, 0, True)
    assert out[0] == "inner" and out[1] is True and out[2] == {}
    levels = [(KNOWN_FN, None), (OTHER, False),
              (KNOWN_FN, None), (OTHER, True)]
    out = seek_gate(object(), 0, 100, levels, {}, 0, 0, 0, 2, 0, 0, False)
    assert out[0] == "inner" and out[1] is False
    assert out[2] == {0x140: 1}


def test_seek_gate_probe_hit_and_miss_counters():
    h32 = 0x12345678
    h = (h32 * 0x9E3779B97F4A7C13) & ((1 << 64) - 1)
    b0, b1 = mask_bits(h)
    base = probe_base(5, h32)
    levels = [(KNOWN_FN, None), (KNOWN_FN, None),
              (KNOWN_FN, None), (OTHER, True)]
    words = {base: (1 << b0) | (1 << b1)}
    out = seek_gate(object(), 0, 100, levels, words, 5, 1, h32,
                    2, 0, 0, True)
    assert out[0] == "inner" and out[2] == {0x140: 1, 0x200: 1}
    words = {base: 0}
    out = seek_gate(object(), 0, 100, levels, words, 5, 1, h32,
                    2, 0, 0, True)
    assert out[0] == "miss" and out[1] is False
    assert out[2] == {0x140: 1, 0x208: 1}


def test_seek_gate_perf_gating_and_timer():
    levels = [(KNOWN_FN, None), (KNOWN_FN, None),
              (KNOWN_FN, None), (OTHER, True)]
    # perf byte 1: no counters, no timer even with a start value.
    out = seek_gate(None, 0, 100, levels, {}, 0, 0, 0, 1, 500, 900, True)
    assert out[2] == {} and out[3] is None
    # perf byte 3 with a start value: timer elapsed added.
    out = seek_gate(None, 0, 100, levels, {}, 0, 0, 0, 3, 500, 900, True)
    assert out[2] == {0x140: 1} and out[3] == 400
    # perf byte 3 with a zero start value: no timer add.
    out = seek_gate(None, 0, 100, levels, {}, 0, 0, 0, 3, 0, 900, True)
    assert out[3] is None


def test_packet_checks():
    records = json.load(open(os.path.join(PACKET, "records.json")))
    assert records["window"]["start"] == "0x5f08c40"
    assert records["window"]["end"] == "0x5f09047"
    assert records["window"]["size_bytes"] == 1031
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["census"]["direct_calls"] == []
    assert records["census"]["tail_jumps"] == []
    assert records["census"]["relative_slots"] == ["0x64cc670"]
    assert records["census"]["qword_hits_file_offsets"] == ["0x10c060"]
    for name in ("window-5f08c40.objdump.txt",
                 "timer-5f05950.objdump.txt"):
        path = os.path.join(PACKET, name)
        assert os.path.getsize(path) > 0
        assert "endbr64" in open(path).read() or "timer" in name


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


if __name__ == "__main__":
    for fn in TESTS:
        fn()
    print("all %d model tests passed" % len(TESTS))
