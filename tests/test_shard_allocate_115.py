"""Tests for the node #115 shard allocation model (window 0x5f117a0).

Run under pytest when available, or plain python3 (the __main__
runner below) — pytest is not installed on the author's VM.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from shard_allocate_115 import (  # noqa: E402
    MASK64,
    Shard,
    ShardAllocator,
    bump_allocate,
    entry_route,
    fallback_decision,
    grow_size,
    round_up8,
    shard_index,
)


def test_round_up8():
    assert round_up8(0) == 0  # sub wraps, or fills, add wraps
    assert round_up8(1) == 8
    assert round_up8(8) == 8
    assert round_up8(9) == 16
    assert round_up8(15) == 16
    assert round_up8(16) == 16
    assert round_up8(17) == 24


def test_entry_route():
    # TLS path needs (field40 >> 2) >= size AND quantum == 0.
    assert entry_route(400, 100, 0) == "tls"
    assert entry_route(400, 101, 0) == "global"  # 400 >> 2 == 100 < 101
    assert entry_route(400, 100, 8) == "global"  # quantum nonzero
    assert entry_route(400, 99, 0) == "tls"
    assert entry_route(0, 0, 0) == "tls"  # 0 >= 0 with quantum 0


def test_shard_index():
    assert shard_index(0b101101, 0) == 0  # shift 0: mask is empty
    assert shard_index(0b101101, 1) == 1
    assert shard_index(0b101101, 3) == 0b101
    assert shard_index(0b101101, 6) == 0b101101
    assert shard_index(0b101101, 64) == 0  # CL masking: 64 & 63 == 0
    assert shard_index(0b101101, 65) == 1  # 65 & 63 == 1


def test_grow_size():
    # F = 400: F >> 1 == 200, 2 * F == 800.
    assert grow_size(400, 199) == 400
    assert grow_size(400, 200) == 200  # boundary: not < F >> 1
    assert grow_size(400, 799) == 799
    assert grow_size(400, 800) == 800  # boundary: not < 2 * F
    assert grow_size(400, 5000) == 800
    assert grow_size(0, 0) == 0


def test_bump_allocate():
    assert bump_allocate(1000, 64, 64) == (1000, 1064, 0)  # exact fit
    assert bump_allocate(1000, 63, 64) is None  # one short
    assert bump_allocate(1000, 0, 0) == (1000, 1000, 0)


def test_shard_bump_end_to_end():
    shard = Shard(cursor=5000, remaining=128, locked=True)
    assert shard.bump(64) == 5000
    assert (shard.cursor, shard.remaining, shard.locked) == (5064, 64, False)


def test_refill_grow_and_bump():
    alloc = ShardAllocator(field40=400, shards=[])
    alloc.snap_remaining = 100  # < size 128: grow arm, not direct
    alloc.member_remaining = 900
    shard = Shard(cursor=7000, remaining=16, locked=True)
    calls = []
    alloc.arena_allocate = lambda *a: (calls.append(a), 0x8000)[1]
    result = alloc.allocate_shard(shard, 128, logger=None)
    # grow: snap 100 < 200 == F >> 1, so g == F == 400.
    assert result == 0x8000
    assert shard.cursor == 0x8000 + 128
    assert shard.remaining == 400 - 128
    assert alloc.snap_remaining == 900  # refreshed from member field
    assert alloc.global_locked is False
    assert shard.locked is False


def test_refill_direct_path_gate_equal():
    alloc = ShardAllocator(field40=400, shards=[])
    alloc.snap_remaining = 512  # covers size
    alloc.gate_a = alloc.gate_b = 0x42
    seen = []
    alloc.post_direct = lambda obj: seen.append("post")
    alloc.arena_allocate = lambda *a: 0x9000
    shard = Shard(cursor=7000, remaining=16, locked=True)
    result = alloc.allocate_shard(shard, 128, logger="log")
    assert result == 0x9000
    assert seen == ["post"]
    # Direct path leaves the shard cursor/remaining untouched.
    assert (shard.cursor, shard.remaining) == (7000, 16)
    assert shard.locked is False


def test_refill_direct_path_gate_unequal_goes_grow():
    alloc = ShardAllocator(field40=400, shards=[])
    alloc.snap_remaining = 512
    alloc.gate_a, alloc.gate_b = 1, 2
    alloc.arena_allocate = lambda *a: 0x8000
    shard = Shard(cursor=7000, remaining=16, locked=True)
    result = alloc.allocate_shard(shard, 128, logger=None)
    # grow: snap 512 in [200, 800), so g == snap == 512.
    assert result == 0x8000
    assert shard.remaining == 512 - 128


def test_refill_grow_smaller_than_size_wraps_literally():
    alloc = ShardAllocator(field40=64, shards=[])
    alloc.snap_remaining = 1000  # >= 2 * F, so g == 128 < size 200
    alloc.gate_a, alloc.gate_b = 1, 2  # unequal: grow, not direct
    alloc.arena_allocate = lambda *a: 0x8000
    shard = Shard(cursor=0, remaining=0, locked=True)
    result = alloc.allocate_shard(shard, 200, logger=None)
    assert result == 0x8000
    assert shard.remaining == (128 - 200) & MASK64  # literal wrap


def test_global_path_snapshots_and_unlocks():
    alloc = ShardAllocator(field40=400, shards=[])
    alloc.member_remaining, alloc.member_940, alloc.member_counter = 11, 22, 33
    alloc.arena_allocate = lambda *a: 0x7777
    result = alloc.allocate_global(64, 0, logger="log")
    assert result == 0x7777
    assert (alloc.snap_remaining, alloc.snap_940, alloc.snap_counter) == (11, 22, 33)
    assert alloc.global_locked is False


def test_fallback_decision():
    assert fallback_decision(True, False) == 1
    assert fallback_decision(False, True) == 0x23
    assert fallback_decision(False, False) is None


def test_packet_records_digest():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-shard-allocate-115", "records.json")
    records = json.load(open(packet))
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["windows"]["main"]["start"] == "0x5f117a0"
    assert records["windows"]["main"]["end"] == "0x5f11c38"


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
        print("PASS", fn.__name__)
    print("ALL %d TESTS PASSED" % len(TESTS))
