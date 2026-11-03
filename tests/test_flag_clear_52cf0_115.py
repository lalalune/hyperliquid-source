"""Tests for the node #115 threshold flag-clear model (0x5d52cf0).

Target-grounded expectations: the no-op acquire stub, the
end-cursor stop, the unsigned above-threshold stop (AT&T
`cmp (%rax),%rbx` + `jb` exits when the threshold is
unsigned-less than the key, so a key equal to the threshold
is cleared), the +0x10-only writes in walk order, the
0x200-byte chunk switch through the next map slot, and the
closing broadcast, plus input guards. Run from the repository
root:

    python3 tests/test_flag_clear_52cf0_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from flag_clear_52cf0_115 import (ACQUIRE_CALLEE, BROADCAST_CALLEE,
                                  CHUNK_SIZE, CHUNK_END_OFFSET,
                                  COND_OFFSET, CURSOR_OFFSET,
                                  END_OFFSET, ENTRY_SIZE,
                                  FLAG_OFFSET, LOCK_OFFSET,
                                  NODE_SLOT_OFFSET, Chunk, Entry,
                                  flag_clear)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def chunk(base, keys):
    return Chunk(base, [Entry(k) for k in keys])


def owner(cursor, chunk_end, end, slots, chunks):
    return {"cursor": cursor, "chunk_end": chunk_end, "end": end,
            "slots": slots, "chunks": chunks}


def run(own, threshold):
    events = []
    result = flag_clear(own, threshold, events)
    return result, events


def main():
    check("entry size", ENTRY_SIZE == 0x20)
    check("chunk size", CHUNK_SIZE == 0x200)
    check("flag offset", FLAG_OFFSET == 0x10)
    check("cursor offset", CURSOR_OFFSET == 0xB30)
    check("chunk end offset", CHUNK_END_OFFSET == 0xB40)
    check("end offset", END_OFFSET == 0xB50)
    check("node slot offset", NODE_SLOT_OFFSET == 0xB48)
    check("lock offset", LOCK_OFFSET == 0x9C8)
    check("cond offset", COND_OFFSET == 0xB70)
    check("acquire callee", ACQUIRE_CALLEE == 0x60D5390)
    check("broadcast callee", BROADCAST_CALLEE == 0x60D57C0)

    # 1. Empty sequence: cursor == end at once; acquire and
    # broadcast still happen, nothing is cleared.
    c0 = chunk(0x1000, [10] * 16)
    own = owner(0x1000, 0x1200, 0x1000, [0x1000, 0x1200],
                {0x1000: c0})
    result, events = run(own, 7)
    check("empty returns", result == "returned")
    check("empty events",
          events == ["acquire stub called (0x60d5390, owner +0x9c8, no-op)",
                     "broadcast called (0x60d57c0, owner +0xb70)"])
    check("empty clears nothing",
          all(e.flag == 1 for e in c0.entries))

    # 2. One full chunk, all keys at or below the threshold:
    # all 16 flags cleared in order, then the next map slot
    # equals the end cursor and the walk stops. The key equal
    # to the threshold (7) is cleared, not stopped on -- the
    # boundary that catches an inverted comparison.
    c0 = chunk(0x1000, [7, 6, 5] + [7] * 13)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    result, events = run(own, 7)
    check("full chunk returns", result == "returned")
    check("full chunk clears all",
          all(e.flag == 0 for e in c0.entries))
    check("full chunk clear count",
          sum(1 for e in events if e.startswith("cleared")) == 16)
    check("full chunk ends with broadcast",
          events[-1] == "broadcast called (0x60d57c0, owner +0xb70)")

    # 3. Above-threshold stop: the first key above the
    # threshold stops the walk at once; later entries, in the
    # same chunk, keep their flags, but the broadcast still runs.
    # The head key 5 (at or below 7) clears; the key 8 stops.
    c0 = chunk(0x1000, [5, 8, 20] + [30] * 13)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    _r, events = run(own, 7)
    check("stop clears only the head",
          [e.flag for e in c0.entries[:4]] == [0, 1, 1, 1])
    check("stop event names the key",
          any("above threshold" in e and "0x8" in e for e in events))
    check("stop still broadcasts",
          events[-1] == "broadcast called (0x60d57c0, owner +0xb70)")

    # 3b. One above the threshold stops; exactly at it clears.
    c0 = chunk(0x1000, [7, 8] + [7] * 14)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    _r, _e = run(own, 7)
    check("threshold-equal clears, threshold-plus-one stops",
          [e.flag for e in c0.entries[:3]] == [0, 1, 1])

    # 4. Multi-chunk: the first chunk clears fully, the walk
    # switches through the next map slot (chunk end becomes
    # base + 0x200), and the second chunk's first above-threshold
    # key stops it there.
    c0 = chunk(0x1000, [5] * 16)
    c1 = chunk(0x2000, [9, 5] + [5] * 14)
    own = owner(0x1000, 0x1200, 0x2200, [0x1000, 0x2000],
                {0x1000: c0, 0x2000: c1})
    _r, events = run(own, 7)
    check("multi-chunk clears first chunk",
          all(e.flag == 0 for e in c0.entries))
    check("multi-chunk stops in second chunk",
          [e.flag for e in c1.entries[:2]] == [1, 1])
    check("multi-chunk clear count",
          sum(1 for e in events if e.startswith("cleared")) == 16)

    # 5. Partial first chunk: starting mid-chunk clears from
    # the cursor onward, not from the chunk base.
    c0 = chunk(0x1000, [99] * 4 + [8, 9] + [99] * 10)
    own = owner(0x1080, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    _r, events = run(own, 100)
    check("partial start keeps the head entries",
          all(e.flag == 1 for e in c0.entries[:4]))
    check("partial start clears from the cursor",
          all(e.flag == 0 for e in c0.entries[4:]))

    # 6. Unsigned comparison: the maximum key is above any
    # small threshold and stops at once; a zero key is at or
    # below any threshold and clears.
    c0 = chunk(0x1000, [0xFFFFFFFFFFFFFFFF, 0] + [5] * 14)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    _r, _e = run(own, 1)
    check("unsigned max key stops",
          c0.entries[0].flag == 1)
    c0 = chunk(0x1000, [0, 0xFFFFFFFFFFFFFFFF] + [5] * 14)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    _r, _e = run(own, 1)
    check("unsigned zero key clears",
          c0.entries[0].flag == 0)
    check("unsigned max key stops after zero",
          c0.entries[1].flag == 1)

    # 7. Only the +0x10 byte is written: keys are unchanged.
    c0 = chunk(0x1000, [42] * 16)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000, 0x1200],
                {0x1000: c0})
    run(own, 100)
    check("keys unchanged",
          all(e.key == 42 for e in c0.entries))

    # 8. Input guards: a null owner raises; a map slot list
    # that runs out at a chunk end raises instead of reading
    # past the sequence unchecked.
    try:
        run(None, 1)
        check("null owner raises", False)
    except ValueError:
        check("null owner raises", True)
    c0 = chunk(0x1000, [50] * 16)
    own = owner(0x1000, 0x1200, 0x1200, [0x1000],
                {0x1000: c0})
    try:
        run(own, 100)
        check("slot exhaustion raises", False)
    except ValueError:
        check("slot exhaustion raises", True)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
