"""Tests for tools/stats_snapshot_insert_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_stats_snapshot_insert_115.py

Every expectation is grounded in the packet
research/work-items/RE-001-stats-snapshot-insert-115/: the
state-init stores, the %010d seek, the version-key literals
and the gate, the delimited-key and decimal parse semantics,
the node layout, the vtable slot tables, the locked lookup
and the merge/replace rules all come from the excerpts and
records in that packet.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stats_snapshot_insert_115 import (
    FORMAT_VERSION_KEY, COMPATIBLE_VERSION_KEY, SEEK_FORMAT,
    NOT_PREALLOCATED_MSG, NODE_SIZE, MAP_NODE_SIZE, SSO_LIMIT,
    INSERT_ADDR, CALLER_ADDR, WRAPPER_ADDR,
    VTABLE_A, VTABLE_B, SLOTS_A, SLOTS_B,
    OK, INVALID_ARGUMENT,
    Status, state_init_bytes, format_seek_bound, compare_keys,
    parse_decimal, parse_delimited_key, MapNode, SnapshotNode,
    node_init, locked_lookup, map_copy, lower_bound_position,
    insert, wrapper_refresh, slot3_a_refresh, caller_build,
)

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def expect_error(kind, fn, label):
    CHECKS[0] += 1
    try:
        fn()
    except kind:
        return
    raise AssertionError("check failed (no %s): %s" % (kind.__name__, label))


def test_constants():
    check(INSERT_ADDR == 0x606EF50, "insert address")
    check(CALLER_ADDR == 0x5D4CC80, "caller address")
    check(WRAPPER_ADDR == 0x606F920, "wrapper address")
    check(VTABLE_A == 0x64D2C28 and VTABLE_B == 0x64D2C90, "vtables")
    check(len(SLOTS_A) == 8 and len(SLOTS_B) == 8, "8 slots per vtable")
    check(SLOTS_A[5] == SLOTS_B[5] == 0x606C170, "slot 5 shared")
    check(SLOTS_B[3] == WRAPPER_ADDR, "wrapper is type B slot 3")
    check(NODE_SIZE == 0x70 and MAP_NODE_SIZE == 0x48, "node sizes")
    check(len(FORMAT_VERSION_KEY) == 35, "format key is 35 bytes")
    check(len(COMPATIBLE_VERSION_KEY) == 39, "compatible key is 39")
    check(SEEK_FORMAT == "%010d", "seek format")
    check(NOT_PREALLOCATED_MSG == "stats_iterator not preallocated.",
          "error message")


def test_state_init_bytes():
    buf = state_init_bytes()
    check(len(buf) == 0x90, "state struct is 0x90 bytes")
    check(int.from_bytes(buf[0x2C:0x34], "little") == 0x101,
          "state +0x2c = 0x101")
    check(int.from_bytes(buf[0x78:0x80], "little") == (1 << 64) - 1,
          "state +0x78 = -1")
    check(int.from_bytes(buf[0x84:0x88], "little") == 4,
          "state +0x84 = 4")
    check(int.from_bytes(buf[0x88:0x8A], "little") == 0x100,
          "state +0x88 = 0x100")
    rest = bytearray(buf)
    for span in ((0x2C, 0x34), (0x78, 0x80), (0x84, 0x88), (0x88, 0x8A)):
        rest[span[0]:span[1]] = b"\x00" * (span[1] - span[0])
    check(all(b == 0 for b in rest), "state is zero elsewhere")


def test_format_seek_bound():
    check(format_seek_bound(7, 100) == b"0000000100", "seek takes max()")
    check(format_seek_bound(100, 7) == b"0000000100", "seek takes max()")
    check(format_seek_bound(1234567890, 9999999999) == b"9999999999",
          "seek takes the larger bound at the 10-digit edge")
    check(format_seek_bound(0, 0) == b"0000000000", "seek zero")


def test_compare_keys():
    check(compare_keys(b"abc", b"abc") == 0, "equal keys compare 0")
    check(compare_keys(b"abd", b"abc") == 1, "later byte wins")
    check(compare_keys(b"ab", b"abc") == -1, "shorter sorts first")
    check(compare_keys(b"abc", b"ab") == 1, "longer sorts last")
    check(compare_keys(b"", b"a") == -1, "empty is smallest")
    check(compare_keys(b"", b"") == 0, "empty equals empty")
    check(compare_keys(b"a\x00", b"a\x01") == -1, "NUL byte compares")
    check(compare_keys(b"\xff", b"\x00") == 255, "byte difference")


def test_parse_decimal():
    check(parse_decimal("0") == 0, "zero")
    check(parse_decimal("  42") == 42, "leading whitespace skipped")
    check(parse_decimal("+7") == 7, "plus sign")
    check(parse_decimal("-1") == (1 << 64) - 1, "minus wraps mod 2**64")
    check(parse_decimal("123abc") == 123, "trailing junk ignored")
    check(parse_decimal("5K") == 5 << 10, "K shifts 10")
    check(parse_decimal("3m") == 3 << 20, "lowercase m shifts 20")
    check(parse_decimal("2G") == 2 << 30, "G shifts 30")
    check(parse_decimal("1t") == 1 << 40, "lowercase t shifts 40")
    check(parse_decimal("1Kx") == 1 << 10, "suffix then junk ignored")
    check(parse_decimal("18446744073709551615") == (1 << 64) - 1,
          "max u64 parses")
    expect_error(ValueError, lambda: parse_decimal(""),
                 "empty input has no digits")
    expect_error(ValueError, lambda: parse_decimal("abc"),
                 "no digits at all")
    expect_error(ValueError, lambda: parse_decimal("  +  "),
                 "sign alone has no digits")
    expect_error(OverflowError,
                 lambda: parse_decimal("18446744073709551616"),
                 "u64 overflow throws")
    expect_error(OverflowError, lambda: parse_decimal("9" * 25),
                 "huge input overflows")


def test_parse_delimited_key():
    seq, key = parse_delimited_key(b"12#foo", 0)
    check(seq == 12 and key == b"foo", "prefix + suffix")
    seq, key = parse_delimited_key(b"12#", 0)
    check(seq == 12 and key == b"", "hash last leaves empty key")
    seq, key = parse_delimited_key(b"nohash", 0)
    check(seq == (1 << 64) - 1 and key == b"", "no hash -> -1, empty")
    seq, key = parse_delimited_key(b"5#x", 10)
    check(seq == (1 << 64) - 1 and key == b"",
          "prefix below bound -> -1, empty")
    seq, key = parse_delimited_key(b"10#x", 10)
    check(seq == 10 and key == b"x", "prefix at bound is kept")
    seq, key = parse_delimited_key(b"1K#v", 0)
    check(seq == 1024 and key == b"v", "suffix shift in the prefix")
    seq, key = parse_delimited_key(b"3#a#b", 0)
    check(seq == 3 and key == b"a#b", "first hash splits, rest kept")


def test_map_node():
    short = MapNode(b"abc", 9)
    check(not short.heap and short.key == b"abc" and short.value == 9,
          "short key is SSO")
    edge = MapNode(b"x" * 15, 1)
    check(not edge.heap, "len 15 is still SSO")
    long = MapNode(b"x" * 16, 1)
    check(long.heap, "len 16 goes to the heap")
    check(MapNode(b"k", (1 << 64) + 5).value == 5,
          "value wraps mod 2**64")


def test_snapshot_node_slots():
    node = SnapshotNode("A", {"flag_4c9": 0}, 0, 100)
    check(node.vtable == VTABLE_A, "type A vtable")
    check(node.slot2_flag() == 1, "slot 2 reads the flag byte")
    node.fields["flag"] = 0
    check(node.slot2_flag() == 0, "slot 2 tracks the flag")
    node.fields["bound"] = 77
    check(node.slot4_bound() == 77, "slot 4 reads +0x8")
    check(node.slot5() == -1, "slot 5 returns -1")
    check(node.slot6_payload_ptr() == "node+0x20", "slot 6 returns &+0x20")
    node.fields["header_u32"] = 5
    node.fields["header_u16"] = 7
    node.fields["header_ptr"] = "hdr"
    owner = {"header_u32": 0, "header_u16": 0, "header_ptr": "old"}
    node.slot7_copy_header(owner)
    check(owner == {"header_u32": 5, "header_u16": 7,
                    "header_ptr": "hdr"}, "slot 7 copies the header")
    node.fields["header_ptr"] = None
    owner2 = {"header_u32": 0, "header_u16": 0, "header_ptr": "old"}
    node.slot7_copy_header(owner2)
    check(owner2["header_ptr"] is None, "slot 7 nulls a null ptr")
    node.delete()
    check(node.entries == {} and node.released, "dtor frees the map")


def test_locked_lookup():
    tree = [(10, {b"a": 1}), (20, {b"b": 2}), (30, {b"c": 3})]
    key, entries = locked_lookup(tree, 15, 25)
    check(key == 20 and entries == {b"b": 2}, "first key in range wins")
    key, entries = locked_lookup(tree, 30, 40)
    check(key == 30, "upper bound is exclusive of the next key")
    key, entries = locked_lookup(tree, 31, 40)
    check(key is None and entries is None, "no key in range is a miss")
    key, entries = locked_lookup([], 0, 100)
    check(key is None, "empty tree misses")
    dst = {b"old": 9}
    map_copy(dst, {b"new": 1})
    check(dst == {b"new": 1}, "map copy replaces the old map")


def test_lower_bound_position():
    check(lower_bound_position([], b"a") == (None, "header"),
          "empty map inserts at the end")
    check(lower_bound_position([b"a", b"c"], b"b") == (b"c", b"c"),
          "middle key inserts before its successor")
    check(lower_bound_position([b"a", b"c"], b"a") == (b"a", None),
          "duplicate reports insert_pos None")
    check(lower_bound_position([b"a"], b"z") == (None, "header"),
          "key after all entries inserts at the end")


def _entries():
    return [
        (b"5#alpha", b"100"),
        (b"6#beta", b"200"),
        (b"7#" + FORMAT_VERSION_KEY, b"999"),
        (b"8#alpha", b"300"),
        (b"9#gamma", b"1K"),
    ]


def test_insert_happy_path():
    node = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    node.entries = {b"stale": 1}
    insert(node, 0, 100, 42, _entries())
    check(node.fields["bound"] == 5, "node+0x8 gets the first sequence")
    check(node.flag == 1, "flag stays set on success")
    check(node.entries == {b"alpha": 100, b"beta": 200, b"gamma": 1024},
          "map holds parsed values, version key skipped, "
          "first alpha wins")
    check(b"stale" not in node.entries, "merge replaces the old map")
    check(node.released, "iterator released on the merge path")


def test_insert_early_exits():
    null_node = SnapshotNode("B", None, 0, 100)
    insert(null_node, 0, 100, 0, _entries())
    check(null_node.flag == 0, "null source clears the flag")
    check(null_node.entries == {}, "null source leaves the map alone")
    empty = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    empty.entries = {b"keep": 1}
    insert(empty, 0, 100, 0, [])
    check(empty.flag == 0 and empty.entries == {b"keep": 1},
          "empty iterator clears the flag and leaves the map")
    over = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    over.entries = {b"keep": 2}
    insert(over, 0, 50, 0, [(b"60#x", b"1")])
    check(over.flag == 0 and over.entries == {b"keep": 2},
          "first sequence above the upper bound aborts")
    below = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    insert(below, 10, 100, 0, [(b"5#x", b"1"), (b"20#y", b"2")])
    check(below.flag == 0 and below.entries == {},
          "first prefix below the parse bound aborts")
    nohash = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    insert(nohash, 0, 100, 0, [(b"plain", b"1")])
    check(nohash.flag == 0 and nohash.entries == {},
          "first entry without '#' aborts")


def test_insert_version_key_prefix():
    node = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    entries = [
        (b"1#k", b"1"),
        (b"2#" + FORMAT_VERSION_KEY + b"extra", b"2"),
        (b"3#" + FORMAT_VERSION_KEY[:20], b"3"),
    ]
    insert(node, 0, 100, 0, entries)
    check(node.entries == {b"k": 1,
                           FORMAT_VERSION_KEY + b"extra": 2,
                           FORMAT_VERSION_KEY[:20]: 3},
          "only the exact 35-byte version key is skipped")


def test_wrapper_and_slot3():
    node = SnapshotNode("B", {"flag_4c9": 1}, 0, 100)
    node.fields["bound"] = 4
    wrapper_refresh(node, 0, [(b"5#a", b"10"), (b"6#b", b"20")])
    check(node.fields["bound"] == 5,
          "wrapper passes 1+*(node+0x8) as the bound")
    check(node.entries == {b"a": 10, b"b": 20}, "wrapper fills the map")
    node2 = SnapshotNode("A", {"flag_4c9": 0}, 0, 100)
    node2.fields["bound"] = 4
    tree = [(5, {b"hit": 7})]
    slot3_a_refresh(node2, 0, 100, tree)
    check(node2.fields["bound"] == 5 and node2.flag == 1,
          "slot 3 A refreshes through the locked lookup")
    check(node2.fields["payload"] == {b"hit": 7},
          "slot 3 A copies the hit map into +0x20")


def test_node_init_paths():
    tree = [(10, {b"a": 1}), (20, {b"b": 2})]
    node = SnapshotNode("A", {"flag_4c9": 0}, 0, 100)
    check(node_init(node, 15, 25, tree) == 1, "lookup hit returns 1")
    check(node.fields["bound"] == 20 and node.fields["payload"] == {b"b": 2},
          "hit writes the key and the map copy")
    check(node.flag == 1, "hit sets the flag")
    node2 = SnapshotNode("A", {"flag_4c9": 0}, 0, 100)
    check(node_init(node2, 50, 60, tree) == 0, "lookup miss returns 0")
    check(node2.fields["bound"] == 0 and node2.fields["payload"] is None,
          "miss writes nothing")
    check(node2.flag == 0, "miss clears the flag")


def test_caller_build():
    status, node = caller_build({}, None, 0, 100, None)
    check(not status.ok() and status.code == INVALID_ARGUMENT,
          "null slot is InvalidArgument")
    check(status.message == NOT_PREALLOCATED_MSG, "null slot message")
    check(node is None, "null slot builds nothing")
    owner = {"header_u32": 9, "header_u16": 9, "header_ptr": "old"}
    slot = {"node": None}
    status, node = caller_build(
        owner, {"flag_4c9": 0}, 15, 25, slot,
        source_tree=[(20, {b"b": 2})])
    check(status.ok() and node.node_type == "A", "flag 0 builds type A")
    check(node.fields["bound"] == 20, "type A path runs the lookup")
    check(owner == {"header_u32": 0, "header_u16": 0,
                    "header_ptr": None},
          "slot 7 resets the owner header")
    check(slot["node"] is node, "slot holds the new node")
    old = node
    status, node2 = caller_build(
        owner, {"flag_4c9": 1}, 0, 100, slot,
        source_bound=0, entries=_entries())
    check(node2.node_type == "B", "nonzero flag builds type B")
    check(old.released, "the old node is deleted on replace")
    check(node2.entries == {b"alpha": 100, b"beta": 200,
                            b"gamma": 1024},
          "type B path runs the insert")


def main():
    test_constants()
    test_state_init_bytes()
    test_format_seek_bound()
    test_compare_keys()
    test_parse_decimal()
    test_parse_delimited_key()
    test_map_node()
    test_snapshot_node_slots()
    test_locked_lookup()
    test_lower_bound_position()
    test_insert_happy_path()
    test_insert_early_exits()
    test_insert_version_key_prefix()
    test_wrapper_and_slot3()
    test_node_init_paths()
    test_caller_build()
    print("%d checks passed" % CHECKS[0])


if __name__ == "__main__":
    main()
