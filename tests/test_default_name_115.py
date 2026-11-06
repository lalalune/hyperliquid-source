#!/usr/bin/env python3
"""Tests for tools/default_name_115.py (node #115).

Run from the repository root:
    python3 tests/test_default_name_115.py

Exits 0 and prints "all N tests passed" only when every check
passes. Each check is one target-grounded expectation about the
global default name "nullptr": its construction, the
length-then-memcmp test, the string-equality and map-find helpers,
and the default-name decision at every consumer site, including
boundary and corruption controls (wrong length, wrong bytes,
empty names, missing records).
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import default_name_115 as m

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("FAIL: %s" % label)


def eq(got, want, label):
    CHECKS[0] += 1
    if got != want:
        raise AssertionError("FAIL: %s: got %r want %r" % (label, got, want))


DEFAULT = (b"nullptr", 7)
OTHER = (b"rocksdb", 7)
EMPTY = (b"", 0)


def test_initializer():
    s, atexit = m.initialize_default_name()
    eq(s.ptr, 0x6508990, "init ptr is self+0x10")
    eq(s.length, 7, "init length is 7")
    eq(s.bytes(), b"nullptr", "init bytes are nullptr")
    eq(s.buf, b"nullptr\x00", "init buffer is NUL terminated")
    eq(atexit["func_got"], 0x64ED5D8, "atexit func is the dtor GOT slot")
    eq(atexit["arg"], 0x6508980, "atexit arg is the global")
    eq(atexit["dso_handle"], 0x64EFA20, "atexit dso is __dso_handle")
    eq(m.INIT_ARRAY_SLOT, 141, "initializer is .init_array entry #142")
    eq(m.INIT_ARRAY_ENTRIES, 168, "168 .init_array entries")
    eq(m.GLOBAL_ADDR, 0x6508980, "global address")
    eq(m.GLOBAL_LEN, 7, "global length")
    # Corruption controls: one wrong byte / one wrong length breaks it.
    bad = m.SsoString(ptr=0x6508990, length=7, buf=b"nullpex\x00")
    check(bad.bytes() != b"nullptr", "one wrong byte is not nullptr")
    bad_len = m.SsoString(ptr=0x6508990, length=6, buf=b"nullptr\x00")
    eq(bad_len.bytes(), b"nullpt", "length 6 truncates the name")


def test_is_default_name():
    check(m.is_default_name(b"nullptr", 7), "nullptr len 7 is default")
    check(not m.is_default_name(b"nullptr", 8), "len 8 is not default")
    check(not m.is_default_name(b"nullptr", 6), "len 6 is not default")
    check(not m.is_default_name(b"nullpex", 7), "one byte off is not default")
    check(not m.is_default_name(b"Nullptr", 7), "case matters")
    check(not m.is_default_name(b"", 0), "empty is not default")
    check(not m.is_default_name(b"nullptrX", 8), "prefix plus byte is not")
    # Length is checked before any byte compare: a 7-byte buffer
    # that differs only past the length still counts.
    check(m.is_default_name(b"nullptr\x00junk", 7), "bytes past len ignored")


def test_string_equal():
    check(m.string_equal(DEFAULT, DEFAULT), "equal strings")
    check(m.string_equal(EMPTY, EMPTY), "empty strings equal, no memcmp")
    check(not m.string_equal(DEFAULT, OTHER), "same len, diff bytes")
    check(not m.string_equal(DEFAULT, (b"nullptrX", 8)), "diff len")
    check(not m.string_equal(EMPTY, (b"x", 1)), "empty vs one byte")
    check(m.string_equal((b"a", 1), (b"a", 1)), "one byte equal")


def test_map_find_name():
    entries = [m.MapEntry(b"alpha", (b"alpha", 5)),
               m.MapEntry(b"beta", (b"beta", 4)),
               m.MapEntry(b"nullptr", (b"nullptr", 7))]
    found = m.map_find_name(entries, (b"nullptr", 7), 7)
    check(found is not None and found.record == (b"nullptr", 7),
          "linear find returns the nullptr record")
    check(m.map_find_name(entries, (b"gamma", 5), 7) is None,
          "linear miss returns None")
    check(m.map_find_name(entries, (b"alpha", 4), 7) is None,
          "length mismatch misses even with a shared prefix")
    # Hash path: 21 entries force the > 20 branch.
    big = [m.MapEntry(b"key%02d" % i, (b"key%02d" % i, 5))
           for i in range(21)]
    big.append(m.MapEntry(b"nullptr", (b"nullptr", 7)))
    found = m.map_find_name(big, (b"nullptr", 7), 8)
    check(found is not None and found.record == (b"nullptr", 7),
          "hash find returns the nullptr record")
    check(m.map_find_name(big, (b"key99", 5), 8) is None,
          "hash miss returns None")
    check(m.map_find_name(big, (b"key03", 5), 8).record == (b"key03", 5),
          "hash find returns an early key too")
    # The hash is deterministic and bucketed in range.
    h1 = m._hash_bytes(b"nullptr", m.MAP_HASH_SEED)
    h2 = m._hash_bytes(b"nullptr", m.MAP_HASH_SEED)
    eq(h1, h2, "hash is deterministic")
    check(0 <= h1 % 8 < 8, "bucket in range")
    check(m._hash_bytes(b"nullptr", m.MAP_HASH_SEED) !=
          m._hash_bytes(b"nullpex", m.MAP_HASH_SEED),
          "one byte changes the hash")


def test_create_host():
    eq(m.create_host_decision(b"", 0), "fresh", "empty name -> fresh")
    eq(m.create_host_decision(b"BasicStatistics", 15), "fresh",
       "BasicStatistics -> fresh")
    eq(m.create_host_decision(b"nullptr", 7), "release",
       "nullptr -> release holder")
    eq(m.create_host_decision(b"foo", 3), "find", "other name -> find")
    eq(m.create_host_decision(b"BasicStatistic", 14), "find",
       "14-byte near miss -> find")
    eq(m.create_host_decision(b"BasicStatisticsX", 16), "find",
       "16-byte near miss -> find")
    eq(m.create_host_decision(b"nullpex", 7), "find",
       "7-byte non-default -> find")


def test_resolver_host():
    eq(m.resolver_host_decision(False, False), ("assign_default", None),
       "null delegate -> assign default")
    eq(m.resolver_host_decision(False, True), ("assign_default", None),
       "null delegate wins over the flag")
    eq(m.resolver_host_decision(True, True), ("clear", None),
       "flag set -> clear the output name")
    eq(m.resolver_host_decision(True, False, (b"resolved", 8)),
       ("assign_resolver", (b"resolved", 8)),
       "resolver result is assigned otherwise")


def test_twins():
    # The two entries are one template instantiated twice: same
    # decision logic, different holder-map field offsets.
    for entry in m.TWIN_ENTRIES:
        check(entry in (0x6086B70, 0x60A7420), "twin entry %#x" % entry)
    eq(m.TWIN_HOLDER_OFFSETS, {0x6086B70: 0x630, 0x60A7420: 0x90},
       "twin holder offsets differ by owner struct")
    kw = dict(kind_ac=2, kind_a8=0x15, holder_present=True,
              wrapper_result=True, lookup_record=(b"custom", 6),
              flag_ah=0x04, base_entry=None, candidate_name=(b"custom", 6),
              arg5_present=True)
    # Validator True jumps straight to the tail.
    eq(m.twin_decision(True, **kw), (0, (b"custom", 6), False),
       "validator True + custom record -> assign, return 0")
    # A record named nullptr is never assigned.
    eq(m.twin_decision(True, **{**kw, "lookup_record": DEFAULT}),
       (1, None, False), "validator True + nullptr record -> return 1")
    # An empty record is never assigned.
    eq(m.twin_decision(True, **{**kw, "lookup_record": EMPTY}),
       (1, None, False), "validator True + empty record -> return 1")
    # A missing record is never assigned.
    eq(m.twin_decision(True, **{**kw, "lookup_record": None}),
       (1, None, False), "validator True + no record -> return 1")
    # Kind outside 0x15..0x16 returns 1 without assigning.
    eq(m.twin_decision(True, **{**kw, "kind_a8": 0x14}),
       (1, None, False), "kind 0x14 -> return 1")
    eq(m.twin_decision(True, **{**kw, "kind_a8": 0x17}),
       (1, None, False), "kind 0x17 -> return 1")
    # No holder control returns 1.
    eq(m.twin_decision(True, **{**kw, "holder_present": False}),
       (1, None, False), "no holder -> return 1")
    # Flag-gated base dereference: a live base entry returns 1.
    eq(m.twin_decision(True, **{**kw, "flag_ah": 0x08,
                                "base_entry": object()}),
       (1, None, False), "flag 0x08 + live base -> return 1")
    eq(m.twin_decision(True, **{**kw, "flag_ah": 0x02,
                                "base_entry": object()}),
       (1, None, False), "flag 0x02 + live base -> return 1")
    eq(m.twin_decision(True, **{**kw, "flag_ah": 0x00,
                                "base_entry": object()}),
       (1, None, False), "flag 0x00 -> return 1 without the deref")
    eq(m.twin_decision(True, **{**kw, "flag_ah": 0x08,
                                "base_entry": None}),
       (0, (b"custom", 6), False),
       "flag 0x08 + null base -> falls to lookup, assigns")
    # Validator False: kind_ac outside 1..3 returns 0, no clear.
    eq(m.twin_decision(False, **{**kw, "kind_ac": 0}),
       (0, None, False), "validator False + kind 0 -> return 0")
    eq(m.twin_decision(False, **{**kw, "kind_ac": 4}),
       (0, None, False), "validator False + kind 4 -> return 0")
    # Validator False + wrapper False returns 0, no clear.
    eq(m.twin_decision(False, **{**kw, "wrapper_result": False}),
       (0, None, False), "wrapper False -> return 0")
    # Validator False + wrapper True clears, then the tail assigns.
    eq(m.twin_decision(False, **kw), (0, (b"custom", 6), False),
       "wrapper True -> clear then tail assigns")
    # Validator False + wrapper True + nullptr record: cleared, return 1.
    eq(m.twin_decision(False, **{**kw, "lookup_record": DEFAULT}),
       (1, None, True), "wrapper True + nullptr record -> cleared, 1")
    # Validator False + lookup miss: cleared, return 1.
    eq(m.twin_decision(False, **{**kw, "lookup_record": None}),
       (1, None, True), "lookup miss -> cleared, return 1")


def test_matcher_wrapper():
    check(not m.matcher_wrapper_decision(1, 2, DEFAULT, DEFAULT),
          "nonzero matcher code -> False")
    check(m.matcher_wrapper_decision(0, 2, DEFAULT, OTHER),
          "kind 2 + candidate is default -> True")
    check(not m.matcher_wrapper_decision(0, 2, OTHER, DEFAULT),
          "kind 2 + candidate is not default -> False")
    check(m.matcher_wrapper_decision(0, 3, DEFAULT, OTHER),
          "kind 3 + candidate is default -> True")
    check(m.matcher_wrapper_decision(0, 3, OTHER, OTHER),
          "kind 3 + candidate equals matcher name -> True")
    check(not m.matcher_wrapper_decision(0, 3, OTHER, (b"zzzzz", 5)),
          "kind 3 + candidate matches neither -> False")
    check(m.matcher_wrapper_decision(0, 1, OTHER, OTHER),
          "other kind + candidate equals matcher name -> True")
    check(not m.matcher_wrapper_decision(0, 1, OTHER, DEFAULT),
          "other kind + candidate differs -> False")
    check(m.matcher_wrapper_decision(0, 1, EMPTY, EMPTY),
          "other kind + both empty -> True")


def test_release_host():
    eq(m.release_host_decision(b"", 0), "clear", "empty -> clear")
    eq(m.release_host_decision(b"nullptr", 7), "clear", "nullptr -> clear")
    eq(m.release_host_decision(b"rocksdb.BuiltinBloomFilter", 26),
       "install", "canonical name -> install")
    eq(m.release_host_decision(b"foo", 3), "find", "other name -> find")
    eq(m.release_host_decision(b"rocksdb.BuiltinBloomFilte", 25),
       "find", "25-byte near miss -> find")
    eq(m.release_host_decision(b"nullpex", 7), "find",
       "7-byte non-default -> find")


def test_find_sites():
    eq(m.find_entry_default_check(0, b""), "clear", "find_entry empty -> clear")
    eq(m.find_entry_default_check(7, b"nullptr"), "clear",
       "find_entry nullptr -> clear")
    eq(m.find_entry_default_check(3, b"foo"), "continue",
       "find_entry other -> continue")
    eq(m.find_entry_default_check(7, b"nullpex"), "continue",
       "find_entry 7-byte non-default -> continue")
    eq(m.find_norm_default_check(0, b""), "assign_fallback",
       "find_norm empty -> assign fallback")
    eq(m.find_norm_default_check(7, b"nullptr"), "assign_fallback",
       "find_norm nullptr -> assign fallback")
    eq(m.find_norm_default_check(3, b"foo"), "equals_search",
       "find_norm other -> equals search")
    eq(m.matcher_default_check(True, True), "assign_default",
       "matcher flag b1 set -> assign default")
    eq(m.matcher_default_check(False, False), "assign_default",
       "matcher flag 04 clear -> assign default")
    eq(m.matcher_default_check(False, True), "other_branch",
       "matcher neither flag -> other branch")


def main():
    test_initializer()
    test_is_default_name()
    test_string_equal()
    test_map_find_name()
    test_create_host()
    test_resolver_host()
    test_twins()
    test_matcher_wrapper()
    test_release_host()
    test_find_sites()
    print("all %d tests passed" % CHECKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
