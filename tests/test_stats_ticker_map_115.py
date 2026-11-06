"""Model tests for tools/stats_ticker_map_115.py
(RE-001-stats-ticker-map-115).

Run directly (pytest is not installed on this VM):
    python3 tests/test_stats_ticker_map_115.py
Exit 0 with "<n> checks passed", else exit 1.

The shard sums use the 0x6070430 contract from #3362
(sum over 2**shard_bits shards of the u64 at
shard_base + shard*0xce40 + ticker*8); the vtable claims
are checked against the packet's vtables.tsv, which
verify.py re-derives from relocations.txt.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import stats_ticker_map_115 as model

PACKET = ROOT / "research" / "work-items" / "RE-001-stats-ticker-map-115"

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        print("FAIL: " + label)
        sys.exit(1)


def main():
    # --- ticker_sum (0x6070430 contract, from #3362) ---
    shards = [{1: 10, 2: 5}, {1: 3, 2: 7}, {1: 0, 2: 0}, {2: 1}]
    check(model.ticker_sum(shards, 2, 1) == 13, "shard sum ticker 1")
    check(model.ticker_sum(shards, 2, 2) == 13, "shard sum ticker 2")
    check(model.ticker_sum(shards, 2, 99) == 0, "missing ticker sums to 0")
    check(model.ticker_sum(shards, 0, 1) == 10, "shard_bits 0 reads shard 0")
    check(model.ticker_sum([{1: 0xFFFFFFFFFFFFFFFF}, {1: 1}], 1, 1) == 0,
          "u64 wrap on shard sum")

    # --- fill_ticker_map (0x6076030) ---
    # use numeric ids via a remapped list: the model takes
    # (ticker_id, name); build from the shards above.
    tickers = [(1, "rocksdb.bytes.read"), (2, "rocksdb.bytes.written")]
    out = {}
    trace = []
    check(model.fill_ticker_map(out, tickers, shards, 2, trace) is True,
          "fill returns True")
    check(out == {"rocksdb.bytes.read": 13,
                  "rocksdb.bytes.written": 13}, "fill contents")
    check(trace == ["lock:+0x38", "unlock:+0x38"], "lock/unlock trace")
    check(model.ticker_map_items(out) == [
        ("rocksdb.bytes.read", 13), ("rocksdb.bytes.written", 13)],
        "map iteration is key-sorted")

    # Old contents are cleared first.
    out = {"stale.key": 999, "rocksdb.bytes.read": 1}
    check(model.fill_ticker_map(out, tickers, shards, 2) is True,
          "refill returns True")
    check(out == {"rocksdb.bytes.read": 13,
                  "rocksdb.bytes.written": 13}, "old contents cleared")

    # Empty ticker vector: cleared map, still True.
    out = {"x": 1}
    check(model.fill_ticker_map(out, [], shards, 2) is True,
          "empty vector returns True")
    check(out == {}, "empty vector clears the map")

    # Null map: False, no lock, no clear.
    trace = []
    check(model.fill_ticker_map(None, tickers, shards, 2, trace) is False,
          "null map returns False")
    check(trace == [], "null map takes no lock")

    # Duplicate names: last occurrence wins (the tree search
    # finds the existing node and overwrites node+0x40).
    dupes = [(1, "same.name"), (2, "same.name")]
    out = {}
    check(model.fill_ticker_map(out, dupes, shards, 2) is True,
          "duplicate fill returns True")
    check(out == {"same.name": 13}, "last duplicate wins")

    # Null name: logic_error with the binary's message, and
    # the mutex is unlocked on the exception path.
    out = {"keep": 1}
    trace = []
    try:
        model.fill_ticker_map(out, [(1, None)], shards, 2, trace)
        check(False, "null name must raise")
    except model.LogicError as exc:
        check(str(exc) == model.LOGIC_ERROR_MESSAGE,
              "logic_error message is the binary's")
    check(trace == ["lock:+0x38", "unlock:+0x38 (exception path)"],
          "exception path unlocks")

    # Long names (>15 chars) take the heap path; the filled
    # map is identical either way (SSO is an implementation
    # detail, not a semantic difference).
    long_name = "rocksdb.db.get.micros.p50"  # 25 chars
    out = {}
    check(model.fill_ticker_map(out, [(1, long_name)], shards, 2) is True,
          "long name fills")
    check(out == {long_name: 13}, "long name contents")

    # --- DB-family vtables (slot 0x2d0 -> rebuild) ---
    tables = {}
    for line in (PACKET / "vtables.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        slot, dbimpl, readonly, compacted, secondary = line.split("\t")
        tables[int(slot, 16)] = {
            "DBImpl": int(dbimpl, 16),
            "DBImplReadOnly": int(readonly, 16),
            "CompactedDBImpl": int(compacted, 16),
            "DBImplSecondary": int(secondary, 16),
        }
    check(len(tables) == model.DB_VTABLE_SLOTS, "151 vtable slots")
    per_class = {name: {slot: tables[slot][name] for slot in tables}
                 for name in model.DB_VTABLES}
    for name in model.DB_VTABLES:
        check(model.rebuild_slot_target(per_class[name]) == model.REBUILD,
              "rebuild slot for " + name)
    identical = sum(
        1 for slot in tables
        if len({tables[slot][n] for n in model.DB_VTABLES}) == 1)
    check(identical == 121, "121 slots identical in all four vtables")
    for name, overrides in model.DB_OVERRIDES.items():
        got = {slot: tables[slot][name] for slot in tables
               if tables[slot][name] != tables[slot]["DBImpl"]}
        check(got == overrides, "override map for " + name)
        check(model.override_slots(name) == sorted(overrides),
              "override slot list for " + name)
    check(len(model.DB_OVERRIDES["DBImplReadOnly"]) == 22,
          "DBImplReadOnly overrides 22 slots")
    check(len(model.DB_OVERRIDES["CompactedDBImpl"]) == 20,
          "CompactedDBImpl overrides 20 slots")
    check(len(model.DB_OVERRIDES["DBImplSecondary"]) == 27,
          "DBImplSecondary overrides 27 slots")
    check(model.REBUILD_SLOT not in
          {s for o in model.DB_OVERRIDES.values() for s in o},
          "no subclass overrides the rebuild slot")

    print("%d checks passed" % CHECKS[0])


if __name__ == "__main__":
    main()
