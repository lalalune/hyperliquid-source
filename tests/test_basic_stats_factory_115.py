"""Tests for tools/basic_stats_factory_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_basic_stats_factory_115.py

End-to-end coverage: create-by-name dispatch, the once-only
registration, the StatisticsImpl layout the ctor builds, the
creator's slot install / delete-old behaviour, the counted_ptr
lifecycle, the PatternEntry matcher (including the sub-pattern
token modes), and the shard-bit rule. Corruption controls check
that a tampered name, flag or prefix length changes the outcome
the way the binary's checks would.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from basic_stats_factory_115 import (  # noqa: E402
    COUNTED_IMPL_VPTR, FACTORY_ENTRY_VPTR, MANAGER, CREATOR,
    OPTIONS_RECORD_OPAQUE, PATTERN_ENTRY_VPTR, SHARD_SIZE,
    STATISTICS_IMPL_VPTR, CountedPtr, FactoryEntry, ObjectLibrary,
    PatternEntry, StatisticsImpl, _Slot, create_by_name,
    register_builtin_statistics, reset_for_tests, shard_bits_for,
    shard_block_size, submatch,
)

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("ok - %s" % label)
    else:
        print("FAIL - %s %s" % (label, detail))
        FAILURES.append(label)


def main():
    # --- shard-bit rule (0x60716d0, default 0x607187c) ---
    for hw, bits in ((1, 3), (8, 3), (9, 4), (16, 4), (17, 5),
                     (32, 5), (33, 6), (64, 6), (65, 7)):
        check("shard bits hw=%d -> %d" % (hw, bits),
              shard_bits_for(hw) == bits)
    check("shard block 8 shards", shard_block_size(3) == 8 * SHARD_SIZE + 0x40,
          hex(shard_block_size(3)))
    try:
        shard_bits_for(1 << 62)
        check("shard bits huge raises", False, "no raise")
    except OverflowError:
        check("shard bits huge raises", True)

    # --- StatisticsImpl layout (ctor 0x6071a00) ---
    obj = StatisticsImpl(hardware_concurrency=4)
    check("ctor vptr", obj.vptr == STATISTICS_IMPL_VPTR, hex(obj.vptr))
    check("ctor size 0x70", obj.size == 0x70)
    check("ctor flags byte 3", obj.flags_byte == 3)
    check("ctor name empty", obj.name == "")
    check("ctor 8 shards hw=4", obj.shard_count == 8)
    check("ctor shard block size",
          obj.shard_block_size == 8 * SHARD_SIZE + 0x40)
    check("ctor options record", obj.options_records == [
        ("StatisticsOptions", "", OPTIONS_RECORD_OPAQUE)],
        repr(obj.options_records))
    check("ctor mutex unlocked", obj.mutex_locked is False)
    check("ctor shared slot empty", obj.shared_slot is None)

    # --- counted_ptr lifecycle (vtables 0x64d2ec8 / 0x64d2f00) ---
    obj2 = StatisticsImpl()
    cp = CountedPtr(obj2, COUNTED_IMPL_VPTR)
    check("counted vptr", cp.vptr == COUNTED_IMPL_VPTR)
    check("counted use 1 weak 1", cp.use_count == 1 and cp.weak_count == 1)
    cp.release()
    check("release disposes object", obj2.destroyed is True)
    check("release destroys control", cp.destroyed is True)
    check("release clears object", cp.obj is None)

    # --- PatternEntry matcher (0x61f8670 / 0x61f8430 / 0x61f8280) ---
    pattern = PatternEntry("BasicStatistics")
    check("pattern vptr", pattern.vptr == PATTERN_ENTRY_VPTR)
    check("pattern flag 1", pattern.flag == 1)
    check("pattern offset 0", pattern.offset == 0)
    check("pattern matches exact", pattern.matches("BasicStatistics"))
    for bad in ("", "BasicStatistic", "BasicStatisticsX",
                "basicstatistics", "Statistics", "Basic Statistics"):
        check("pattern rejects %r" % bad, not pattern.matches(bad))
    check("pattern entry name", pattern.entry_name() == "BasicStatistics")
    # Corruption controls: the flag gates the exact-name path only
    # when sub-patterns exist (0x61f8550); with an empty sub-pattern
    # vector the binary matches exactly regardless of the flag
    # (0x61f8580), and the stored length must equal the query length.
    check("pattern flag 0 still matches when no sub-patterns",
          PatternEntry("BasicStatistics", flag=0).matches("BasicStatistics"))
    flagged = PatternEntry("node", flag=0, sub_patterns=[(3, "")])
    check("pattern flag 0 rejects bare name with sub-patterns",
          not flagged.matches("node"))
    check("pattern flag 0 still matches prefix+token",
          flagged.matches("node42"))
    tampered = PatternEntry("BasicStatistics")
    tampered.name_length = 14
    check("pattern short length rejects",
          not tampered.matches("BasicStatistics"))

    # Sub-pattern token modes (0x61f8280).
    check("submatch mode2 exact", submatch(2, "v1", "v1", 0) == 2)
    check("submatch mode2 rejects", submatch(2, "v1", "v2", 0) == -1)
    check("submatch mode3 int", submatch(3, "", "42", 0) == 2)
    check("submatch mode3 negative", submatch(3, "", "-7", 0) == 2)
    check("submatch mode3 rejects", submatch(3, "", "x", 0) == -1)
    check("submatch mode4 float", submatch(4, "", "1.5", 0) == 3)
    check("submatch mode4 int ok", submatch(4, "", "12", 0) == 2)
    check("submatch mode4 rejects", submatch(4, "", ".", 0) == -1)
    check("submatch mode4 double dot",
          submatch(4, "", "1.2.3", 0) == 3)
    # Prefix-plus-token pattern: "node" + integer token. The bare
    # name still matches when the flag is set (0x61f8550: the exact
    # name is accepted without consulting the sub-patterns).
    prefixed = PatternEntry("node", sub_patterns=[(3, "")])
    check("prefix+int matches", prefixed.matches("node42"))
    check("prefix+int rejects text", not prefixed.matches("nodeX"))
    check("prefix+int matches bare name (flag set)",
          prefixed.matches("node"))
    check("prefix+int rejects trailing",
          not prefixed.matches("node42x"))

    # --- FactoryEntry create / delete-old (0x6071ba0) ---
    reset_for_tests()
    entry = FactoryEntry(PatternEntry("BasicStatistics"))
    check("factory vptr", entry.vptr == FACTORY_ENTRY_VPTR)
    check("factory manager", entry.manager == MANAGER)
    check("factory creator", entry.creator == CREATOR)
    check("factory functor slots zero", entry.functor_slots_zero is True)
    slot = _Slot()
    first = entry.create(slot)
    check("creator installs object", slot.get() is first)
    check("creator object alive", first.destroyed is False)
    second = entry.create(slot)
    check("creator replaces object", slot.get() is second)
    check("creator deletes old occupant", first.destroyed is True)
    check("creator new object alive", second.destroyed is False)
    entry.destroy()
    check("factory destroy clears pattern", entry.pattern is None)

    # --- ObjectLibrary register / lookup (0x6075bc0, 0x5fd1da0) ---
    lib = ObjectLibrary()
    check("library default name", lib.name == "default")
    lib.register("Statistics", FactoryEntry(PatternEntry("BasicStatistics")))
    lib.register("Statistics", FactoryEntry(PatternEntry("Other")))
    check("library two factories",
          len(lib.factories_for("Statistics")) == 2)
    check("library unknown key empty",
          lib.factories_for("Nope") == [])
    check("library unlocked after register", lib.locked is False)

    # --- create-by-name end to end (host 0x6077820) ---
    reset_for_tests()
    status, cp = create_by_name("")
    check("create empty ok", status == "ok" and cp is not None)
    check("create empty object", cp.obj is not None
          and cp.obj.vptr == STATISTICS_IMPL_VPTR)
    check("create empty counted vptr", cp.vptr == COUNTED_IMPL_VPTR)
    check("create empty use 1", cp.use_count == 1 and cp.weak_count == 1)
    check("create empty shards", cp.obj.shard_count == 8)
    check("create empty options record",
          cp.obj.options_records[0][0] == "StatisticsOptions")
    status, cp2 = create_by_name("BasicStatistics")
    check("create BasicStatistics ok", status == "ok" and cp2 is not None)
    check("create BasicStatistics fresh object", cp2.obj is not cp.obj)
    # Once-only: the second call must not re-register.
    reset_for_tests()
    create_by_name("BasicStatistics")
    lib2 = None
    from basic_stats_factory_115 import _default_library
    lib2 = _default_library.get()
    check("once-init one factory",
          len(lib2.factories_for("Statistics")) == 1)
    create_by_name("BasicStatistics")
    check("once-init still one factory",
          len(lib2.factories_for("Statistics")) == 1)
    # Registry path: a name the registered pattern does not match.
    status, cp3 = create_by_name("SomethingElse")
    check("create unknown not_found",
          status == "not_found" and cp3 is None)
    # Full lifecycle: create, release, object destroyed.
    reset_for_tests()
    status, cp4 = create_by_name("BasicStatistics")
    victim = cp4.obj
    cp4.release()
    check("lifecycle release destroys object", victim.destroyed is True)

    print()
    if FAILURES:
        print("FAILED: %d (%s)" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
