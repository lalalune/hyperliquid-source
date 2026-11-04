"""Tests for the node #115 outer allocation model (window 0x5f11c40).

Run under pytest when available, or plain python3 (the __main__
runner below) — pytest is not installed on the author's VM.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from allocate_115 import (  # noqa: E402
    Allocator,
    Shard,
    current_carve,
    entry_route,
    fallback_decision,
    grow_size,
    refill_route,
    shard_bump,
    shard_index,
)


def test_entry_route():
    # TLS path needs (field40 >> 2) >= size; no quantum argument here.
    assert entry_route(400, 100) == "tls"
    assert entry_route(400, 101) == "global"  # 400 >> 2 == 100 < 101
    assert entry_route(400, 99) == "tls"
    assert entry_route(0, 0) == "tls"  # 0 >= 0
    assert entry_route(0, 1) == "global"


def test_shard_index():
    assert shard_index(0b101101, 0) == 0  # shift 0: mask is empty
    assert shard_index(0b101101, 1) == 1
    assert shard_index(0b101101, 3) == 0b101
    assert shard_index(0b101101, 6) == 0b101101
    assert shard_index(0b101101, 64) == 0  # CL masking: 64 & 63 == 0
    assert shard_index(0b101101, 65) == 1  # 65 & 63 == 1
    assert shard_index(0, 6) == 0  # cpuid zero selects shard 0


def test_grow_size():
    # F = 400: F >> 1 == 200, 2 * F == 800. Literal rule from the
    # mov/shr/cmp/cmovb shape: F, then S, then F again — the cmovb
    # only replaces F with S while S < 2 * F.
    assert grow_size(400, 199) == 400
    assert grow_size(400, 200) == 200  # boundary: not < F >> 1
    assert grow_size(400, 799) == 799
    assert grow_size(400, 800) == 400  # boundary: not < 2 * F
    assert grow_size(400, 5000) == 400  # third arm keeps F
    assert grow_size(0, 0) == 0


def test_shard_bump_aligned():
    # Front carve: result is the old cursor, cursor advances.
    assert shard_bump(0x1000, 100, 16) == (0x1000, 0x1010, 84)
    assert shard_bump(0x1000, 16, 16) == (0x1000, 0x1010, 0)  # exact fit
    assert shard_bump(0x1000, 15, 16) is None  # shortfall
    assert shard_bump(0x1000, 100, 0) == (0x1000, 0x1000, 100)  # size 0


def test_shard_bump_unaligned():
    # Back carve: result is the tail, cursor untouched.
    assert shard_bump(0x1000, 100, 7) == (0x1000 + 93, 0x1000, 93)
    assert shard_bump(0x1000, 7, 7) == (0x1000, 0x1000, 0)  # exact fit
    assert shard_bump(0x1000, 6, 7) is None  # shortfall
    # A second unaligned carve continues from the new tail.
    assert shard_bump(0x1000, 93, 5) == (0x1000 + 88, 0x1000, 88)


def test_current_carve():
    # Top carve: result is the new end, both fields shrink.
    assert current_carve(0x2000, 100, 16) == (0x1FF0, 0x1FF0, 84)
    assert current_carve(0x2000, 16, 16) == (0x1FF0, 0x1FF0, 0)
    assert current_carve(0x2000, 15, 16) is None
    assert current_carve(0x2000, 100, 0) == (0x2000, 0x2000, 100)


def test_refill_route():
    base = dict(snapshot_remaining=100, size=16, gate888=7, gate8a8=7,
                gate8d8=9, gate8f8=9, current_remaining=100)
    assert refill_route(**base) == "direct"
    assert refill_route(**{**base, "snapshot_remaining": 15}) == "grow"
    assert refill_route(**{**base, "gate888": 8}) == "grow"
    assert refill_route(**{**base, "gate8d8": 10}) == "grow"
    assert refill_route(**{**base, "current_remaining": 15}) == "slow"


def test_fallback_decision():
    assert fallback_decision(True, False) == 1
    assert fallback_decision(False, True) == 0x23
    assert fallback_decision(False, False) is None


def test_allocate_shard_bump_paths():
    alloc = Allocator(field40=400, shift=2,
                      shards=[Shard(0x1000, 100), Shard(0x2000, 50),
                              Shard(0x3000, 0), Shard(0x4000, 0)])
    assert alloc.allocate(16, cpuid=0) == 0x1000  # aligned front carve
    assert alloc.shards[0].cursor == 0x1010
    assert alloc.shards[0].remaining == 84
    assert alloc.allocate(7, cpuid=0) == 0x1010 + 77  # unaligned tail
    assert alloc.shards[0].cursor == 0x1010  # cursor untouched
    assert alloc.shards[0].remaining == 77
    assert alloc.allocate(8, cpuid=1) == 0x2000  # shard 1
    assert alloc.shards[1].cursor == 0x2008


def test_allocate_global_path():
    alloc = Allocator(field40=60, shift=2, shards=[Shard(0, 0)])
    alloc.cur_end = 0x2000
    alloc.cur_remaining = 100
    alloc.member_940 = 22
    alloc.member_counter = 33
    assert alloc.allocate(16, cpuid=0) == 0x1FF0  # top carve, gate fails
    assert (alloc.cur_end, alloc.cur_remaining) == (0x1FF0, 84)
    assert (alloc.snap_remaining, alloc.snap_940,
            alloc.snap_counter) == (84, 22, 33)
    assert alloc.global_locked is False


def test_allocate_global_slow_arm():
    alloc = Allocator(field40=0, shift=0, shards=[Shard(0, 0)])
    alloc.cur_end = 0x2000
    alloc.cur_remaining = 5
    result = alloc.allocate(16, cpuid=0)
    assert result == 0x10000  # slow stub block
    assert alloc.calls[0] == ("slow", 16)
    assert alloc.global_locked is False


def test_allocate_refill_direct_and_grow():
    alloc = Allocator(field40=400, shift=0, shards=[Shard(0x1000, 10)])
    alloc.snap_remaining = 100
    alloc.gate888 = alloc.gate8a8 = 7
    alloc.gate8d8 = alloc.gate8f8 = 9
    alloc.cur_end = 0x2000
    alloc.cur_remaining = 100
    # Direct: top carve + post-direct, shard untouched.
    assert alloc.allocate(16, cpuid=0) == 0x1FF0
    assert alloc.calls == [("post_direct",)]
    assert (alloc.shards[0].cursor, alloc.shards[0].remaining) == (0x1000, 10)
    # Grow: gates unequal -> fresh block, then bump from it.
    alloc.gate8a8 = 8
    alloc.snap_remaining = 300  # F/2 <= 300 < 2F -> grow = 300
    assert alloc.allocate(16, cpuid=0) == 0x10000  # aligned front carve
    assert alloc.calls[-1] == ("arena", 300)
    assert alloc.shards[0].cursor == 0x10010
    assert alloc.shards[0].remaining == 284


def test_allocate_refill_grow_wrap():
    alloc = Allocator(field40=400, shift=0, shards=[Shard(0x1000, 4)])
    alloc.snap_remaining = 0  # 0 < F/2 -> grow = F = 400
    alloc.cur_remaining = 0
    # Unaligned size from the fresh block carves the tail; a grow
    # smaller than the size would wrap, per the literal rule.
    assert alloc.allocate(7, cpuid=0) == 0x10000 + 393
    assert alloc.shards[0].remaining == 393


def test_packet_records_digest():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-allocate-115", "records.json")
    records = json.load(open(packet))
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["windows"]["main"]["start"] == "0x5f11c40"
    assert records["windows"]["main"]["end"] == "0x5f12162"
    assert records["windows"]["main"]["size_bytes"] == 1314


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
        print("PASS", fn.__name__)
    print("ALL %d TESTS PASSED" % len(TESTS))
