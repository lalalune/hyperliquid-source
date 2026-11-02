"""Tests for tools/shard_array_construct.py (RE-001, node #94 0x516adf0).

pytest-style, with a plain-python3 __main__ runner because pytest
is not installed on this VM.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from shard_array_construct import (  # noqa: E402
    SENTINEL, AllocationFailure, ControlBlock, ShardArray,
    allocation_size, bucket_shift_and_count, construct, release_array,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_count_rule():
    cases = [(0, 3, 8), (1, 3, 8), (8, 3, 8), (9, 4, 16), (16, 4, 16),
             (17, 5, 32), (100, 7, 128), (1024, 10, 1024),
             (1025, 11, 2048)]
    for conc, shift, count in cases:
        got = bucket_shift_and_count(conc)
        check(got == (shift, count),
              "concurrency %d -> %r, want (%d, %d)" % (conc, got, shift, count))


def test_allocation_size_and_overflow():
    check(allocation_size(8) == 0x88, "8 buckets -> 0x88 bytes")
    check(allocation_size(16) == 0x108, "16 buckets -> 0x108 bytes")
    try:
        allocation_size(1 << 59)
    except AllocationFailure:
        pass
    else:
        raise AssertionError("count >> 59 must fail the allocation")


def test_construct_installs_zeroed_slots():
    arr = ShardArray()
    size = construct(arr, 9)
    check(arr.shift == 4, "shift stored before allocation")
    check(size == 0x108, "size 8 + 16*16")
    check(len(arr.slots) == 16, "16 slots installed")
    check(all(s == [None, None] for s in arr.slots),
          "every slot zero-filled")
    check(arr.count == 16, "count is 1 << shift")


def test_construct_small_and_unknown():
    for conc in (0, 8):
        arr = ShardArray()
        check(construct(arr, conc) == 0x88, "conc %d -> 0x88" % conc)
        check((arr.shift, len(arr.slots)) == (3, 8), "conc %d -> 8 slots" % conc)


def test_release_reverse_order_and_delete_size():
    log = []
    blocks = [ControlBlock(1, log) for _ in range(3)]
    slots = [[None, blocks[0]], [None, blocks[1]], [None, blocks[2]]]
    size = release_array(slots, destroyer_log=log)
    check(log == [blocks[2], blocks[1], blocks[0]],
          "destroyer fires in reverse slot order")
    check(size == 8 + 16 * 3, "delete[] size is count*16+8")
    check(all(b.count == 0 for b in blocks), "counts decremented to 0")


def test_release_null_slots_skipped():
    log = []
    slots = [[None, None], [None, ControlBlock(5, log)]]
    release_array(slots, destroyer_log=log)
    check(log == [], "null slot skipped, count 5 kept alive (4, no call)")


def test_release_sentinel_virtuals():
    log = []
    block = ControlBlock(SENTINEL, log)
    release_array([[None, block]], destroyer_log=log)
    check(log == ["virtuals"], "sentinel fires the vtable pair, not destroyer")
    check(block.count == 0, "sentinel word zeroed")


def test_release_old_gt_one_keeps_alive():
    log = []
    block = ControlBlock(3, log)
    release_array([[None, block]], single_threaded=False,
                   destroyer_log=log)
    check(block.count == 2 and log == [], "old 3 -> 2, no destroyer")


def test_release_packed_weak_count_preserved():
    # 0x5169c1a..0x5169c2e and 0x516aeb8..0x516aefd update/test
    # only the low DWORD. A weak count of two avoids the 1/1 sentinel.
    for single_threaded in (False, True):
        log = []
        last = ControlBlock((2 << 32) | 1, log)
        release_array([[None, last]], single_threaded=single_threaded,
                      destroyer_log=log)
        check(last.count == 2 << 32, "upper weak-count DWORD is preserved")
        check(log == [last], "last strong reference invokes destroyer")
        log.clear()
        live = ControlBlock((2 << 32) | 3, log)
        release_array([[None, live]], single_threaded=single_threaded,
                      destroyer_log=log)
        check(live.count == (2 << 32) | 2, "only strong count decrements")
        check(log == [], "remaining strong references keep block alive")


def test_release_null_array():
    check(release_array(None) == 0, "null array releases nothing")


def test_packet_records():
    path = os.path.join(
        ROOT, "research/work-items/RE-001-shard-array-construct-94",
        "records.json")
    records = json.load(open(path))
    check(records["window"]["start"] == "0x516adf0", "window start")
    check(records["window"]["artifact_sha256"].startswith("3b7179cd"),
          "digest bound")
    check(records["census"]["direct_calls"] == ["0x51702e8"],
          "single caller")
    check(records["caller"]["construct"].startswith("sole direct call"),
          "caller record")


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]


def main():
    for test in TESTS:
        test()
    print("all %d tests passed" % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
