"""Tests for the fragmented-range-tombstone construction model.

Run from the repository root:
    python3 tests/test_fragmented_range_tombstones_115.py

All expectations are grounded in the pinned binary evidence
(research/work-items/RE-001-fragmented-range-tombstones-115/):
the ReadOptions init map, the sort/dedup/teardown contracts, and
the host state machine. Random sort checks use fixed seeds so the
run is deterministic.
"""

import random
import sys

sys.path.insert(0, "tools")
import fragmented_range_tombstones_115 as m

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("FAIL: " + label)


def rand_entries(rng, n, dup=False):
    out = []
    for _ in range(n):
        first = rng.randrange(0, 5 if dup else 1000)
        second = rng.randrange(0, 3 if dup else 1000)
        out.append((first, second))
    return out


def test_readopts():
    opts = m.default_readopts()
    check(opts[0x2C] == 0x101, "readopts +0x2c is 0x101")
    check(opts[0x78] == -1, "readopts +0x78 is -1")
    check(opts[0x84] == 4, "readopts +0x84 is 4")
    check(opts[0x88] == 0x0100, "readopts +0x88 is 0x0100")
    check(opts[0x48] == 0, "readopts +0x48 is 0")
    check(opts[0x00] == 0 and opts[0x10] == 0, "readopts zeroes the head")
    check(opts[0x38] == 0 and opts[0x50] == 0, "readopts zeroes the middle")
    check(opts[0x80] == 0 and opts[0x34] == 0, "readopts zero bytes")
    check(len(m.READOPTS_INIT) == 15, "readopts init map has 15 stores")
    check(m.READOPTS_SPAN == 0x8A, "readopts span is 0x8a")
    check(not m.readopts_slot_48_callable(opts), "readopts +0x48 call is dead")


def test_compare():
    check(m.compare_entry((1, 2), (1, 2)) == 0, "compare equal")
    check(m.compare_entry((1, 2), (1, 3)) < 0, "compare second qword")
    check(m.compare_entry((1, 9), (2, 0)) < 0, "compare first qword wins")
    check(m.compare_entry((2, 0), (1, 9)) > 0, "compare first qword wins (2)")
    check(m.compare_entry((0, 0), (0, 1)) < 0, "compare zero first")


def test_depth_limit():
    check(m.depth_limit(0) == -2, "depth 0 -> -2")
    check(m.depth_limit(1) == 0, "depth 1 -> 0")
    check(m.depth_limit(16) == 8, "depth 16 -> 8")
    check(m.depth_limit(17) == 8, "depth 17 -> 8")
    check(m.depth_limit(32) == 10, "depth 32 -> 10")
    check(m.depth_limit(256) == 16, "depth 256 -> 16")


def test_insertion_sort():
    rng = random.Random(115)
    for n in (0, 1, 2, 3, 15, 16, 17, 40):
        for trial in range(5):
            entries = rand_entries(rng, n, dup=(trial % 2 == 0))
            got = m.insertion_sort(entries)
            check(got == sorted(entries), "insertion_sort n=%d trial=%d" % (n, trial))
    check(m.insertion_sort([(3, 1), (1, 9), (1, 2)]) == [(1, 2), (1, 9), (3, 1)],
          "insertion_sort orders by (first, second)")


def test_adjust_heap():
    rng = random.Random(1150)
    for n in (1, 2, 3, 5, 17, 33, 64):
        entries = rand_entries(rng, n)
        heap = m.make_heap(entries)
        for i in range(n):
            left = 2 * i + 1
            right = 2 * i + 2
            if left < n:
                check(m.compare_entry(heap[i], heap[left]) >= 0,
                      "heap parent >= left child n=%d" % n)
            if right < n:
                check(m.compare_entry(heap[i], heap[right]) >= 0,
                      "heap parent >= right child n=%d" % n)
        check(m.sort_heap(heap) == sorted(entries),
              "sort_heap matches sorted n=%d" % n)
    # adjust_heap on a single hole: removing the max leaves a heap.
    entries = [(9, 0), (7, 0), (8, 0), (1, 0), (2, 0), (3, 0), (4, 0)]
    got = m.adjust_heap(entries, 0, len(entries), entries[0])
    check(got[0] == (9, 0), "adjust_heap keeps the max on top")


def test_introsort_loop():
    rng = random.Random(1151)
    for n in (0, 1, 2, 15, 16, 17, 18, 33, 64, 100, 200):
        for trial in range(4):
            entries = rand_entries(rng, n, dup=(trial % 2 == 0))
            got = m.introsort_loop(entries, m.depth_limit(len(entries)))
            # introsort_loop leaves <= 16-element ranges to insertion
            # sort, so finish it the way the host does.
            got = m.final_insertion_sort(got)
            check(got == sorted(entries),
                  "introsort+final n=%d trial=%d" % (n, trial))
    # Reverse-sorted input (the partition's worst shape).
    rev = [(n, 0) for n in range(50, 0, -1)]
    check(m.final_insertion_sort(m.introsort_loop(rev, m.depth_limit(50))) == sorted(rev),
          "introsort reverse-sorted")
    # All-equal input.
    eq = [(7, 7)] * 40
    check(m.final_insertion_sort(m.introsort_loop(eq, m.depth_limit(40))) == eq,
          "introsort all-equal")
    # Depth 0 forces the heapsort fallback.
    entries = rand_entries(random.Random(7), 40)
    got = m.introsort_loop(entries, 0)
    check(m.final_insertion_sort(got) == sorted(entries),
          "introsort depth-0 heapsort fallback")


def test_final_insertion_sort():
    rng = random.Random(1152)
    for n in (0, 1, 16, 17, 50):
        entries = rand_entries(rng, n, dup=True)
        check(m.final_insertion_sort(entries) == sorted(entries),
              "final_insertion_sort n=%d" % n)


def test_sort_index():
    rng = random.Random(1153)
    for n in (0, 1, 2, 16, 17, 33, 100):
        for trial in range(3):
            entries = rand_entries(rng, n, dup=(trial % 2 == 0))
            check(m.sort_index(entries) == sorted(entries),
                  "sort_index (host sequence) n=%d trial=%d" % (n, trial))


def test_dedup():
    check(m.dedup_sorted([]) == [], "dedup empty")
    check(m.dedup_sorted([(1, 2)]) == [(1, 2)], "dedup single")
    check(m.dedup_sorted([(1, 2), (1, 2), (1, 3), (1, 3), (2, 0)]) ==
          [(1, 2), (1, 3), (2, 0)], "dedup adjacent runs")
    check(m.dedup_sorted([(1, 1)] * 5) == [(1, 1)], "dedup all-equal")
    check(m.dedup_sorted([(1, 2), (1, 3)]) == [(1, 2), (1, 3)],
          "dedup keeps distinct seconds")


def test_cleanable():
    seen = []
    c = m.Cleanable()
    c.fn = lambda a, b: seen.append(("head", a, b))
    c.arg1, c.arg2 = "A", "B"
    c.chain = [(lambda a, b: seen.append(("c1", a, b)), "C", "D"),
               (lambda a, b: seen.append(("c2", a, b)), "E", "F")]
    trace = []
    c.do_cleanup(trace)
    check(seen == [("head", "A", "B"), ("c1", "C", "D"), ("c2", "E", "F")],
          "cleanable runs head then chain in order")
    check(trace[0][0] == "head" and trace[1][0] == "chain",
          "cleanable trace kinds")
    check(c.fn is None and c.chain == [], "cleanable zeroes itself")
    c.do_cleanup(trace)
    check(seen == [("head", "A", "B"), ("c1", "C", "D"), ("c2", "E", "F")],
          "cleanable second run is a no-op")


def test_release_tree():
    trace = []
    tree = {"name": "root", "child": {"name": "kid", "child": None,
                                       "sibling": {"name": "kid2", "child": None, "sibling": None}},
            "sibling": {"name": "next", "child": None, "sibling": None}}
    m.release_tree(tree, trace)
    check([t[1] for t in trace] == ["kid", "kid2", "root", "next"],
          "release order is child, node, sibling")
    m.release_tree(None, trace)
    check(len(trace) == 4, "release of None is a no-op")


def test_cache_teardown():
    invoked = []

    def reg(fn_id):
        return lambda arg: invoked.append((fn_id, arg))

    registry = {1: reg(1), 2: reg(2)}
    # Ready cache: sort, dedup, invoke survivors in sorted order,
    # run head + chain, then the common tail.
    cache = m.TombstoneCache(index_entries=[(30, 2), (10, 1), (10, 1), (20, 2)],
                             ready=True)
    cache.cleanable.fn = lambda a, b: invoked.append(("head", a))
    cache.cleanable.arg1 = "H"
    cache.cleanable.chain = [(lambda a, b: invoked.append(("chain", a)), "C", None)]
    cache.nodes_80 = ["n80"]
    cache.tree_60 = {"name": "t60", "child": None, "sibling": None}
    cache.buffers["+0x00"] = "buf"
    trace = []
    cache.teardown(registry, trace)
    check(invoked[:3] == [(1, 10), (2, 20), (2, 30)],
          "teardown invokes deduped entries in sorted order")
    check(("head", "H") in invoked and ("chain", "C") in invoked,
          "teardown runs head and chain cleanups")
    check(trace[0] == "ready_sort" and trace[1] == "ready_dedup",
          "teardown ready trace starts with sort/dedup")
    check("zero_98_b0" in trace and trace[-1] == "delete_cache",
          "teardown zeroes cleanups and deletes the cache")
    check(("free_node_80", "n80") in trace, "teardown frees +0x80 nodes")
    check(("node", "t60") in trace, "teardown releases the +0x60 tree")
    check(("free_buffer", "+0x00") in trace, "teardown frees buffers")
    # Not-ready cache: entries are NOT invoked, array just freed.
    invoked.clear()
    cache2 = m.TombstoneCache(index_entries=[(10, 1)], ready=False)
    trace2 = []
    cache2.teardown(registry, trace2)
    check(invoked == [], "not-ready teardown never invokes entries")
    check("ready_sort" not in trace2 and "free_index_array" in trace2,
          "not-ready teardown frees the array directly")


def test_build_iterator():
    owner = {"+0x10": "user_cmp", "+0x31": 0, "+0x60": "f60",
             "+0x6c": "f6c", "+0xa58": "rep", "+0xc58": "c58"}
    it = m.build_iterator(owner, rep_iterator="rep_iter")
    check(it["+0x00"].startswith("vtable 0x64cc648"), "iterator vtable")
    check(it["+0x30"] == "c58", "iterator +0x30 is owner+0xc58")
    check(it["+0x38"].startswith("vtable 0x64cc610"), "iterator KeyComparator")
    check(it["+0x40"].startswith("vtable 0x64c8ff8"), "iterator InternalKeyComparator")
    check(it["+0x48"] == "user_cmp", "iterator +0x48 is owner+0x10")
    check(it["+0x50"] == "rep_iter", "iterator +0x50 is the rep iterator")
    check(it["+0x5a"] == 1, "iterator +0x5a is owner+0x31 ^ 1")
    check(it["+0x60"] == "f6c" and it["+0x78"] == "f60", "iterator +0x60/+0x78")
    check(it["+0x28"] == 0 and it["+0x68"] == 0 and it["+0x70"] == 0,
          "iterator zero fields")
    owner2 = dict(owner, **{"+0x31": 1})
    check(m.build_iterator(owner2, None)["+0x5a"] == 0,
          "iterator +0x5a flips with owner+0x31")


def test_host():
    fields = {"+0x10": "user_cmp", "+0x31": 0, "+0x60": "f60",
              "+0x6c": "f6c", "+0xa58": "rep", "+0xc58": "c58"}
    # Flag set: early return, nothing built.
    owner = m.Owner(fields, already_built=True,
                    old_cache=m.TombstoneCache(ready=True))
    trace, new_cache = m.construct_fragmented_range_tombstones(
        owner, lambda it: m.TombstoneCache(), {})
    check(trace == ["early_return"], "host early return on +0xa60")
    check(new_cache is None, "host early return builds nothing")
    check(owner.cache is not None, "host early return keeps the old cache")
    # Flag clear, no old cache: build, install, destroy iterator.
    owner = m.Owner(fields, already_built=False, old_cache=None)
    built = []
    trace, new_cache = m.construct_fragmented_range_tombstones(
        owner, lambda it: built.append(it) or m.TombstoneCache(), {})
    check(trace == ["build_iterator", "build_cache", "install_cache",
                    "destroy_iterator", "free_scratch"],
          "host rebuild trace without an old cache")
    check(owner.cache is new_cache, "host installs the new cache")
    check(built and built[0]["+0x00"].startswith("vtable 0x64cc648"),
          "host builds the temp iterator first")
    # Flag clear with a live old cache: the teardown runs.
    old = m.TombstoneCache(index_entries=[(5, 9)], ready=True)
    registry = {9: lambda arg: None}
    owner = m.Owner(fields, already_built=False, old_cache=old)
    trace, _ = m.construct_fragmented_range_tombstones(
        owner, lambda it: m.TombstoneCache(), registry)
    check("ready_sort" in trace and "delete_cache" in trace,
          "host rebuild tears down the live old cache")


def main():
    test_readopts()
    test_compare()
    test_depth_limit()
    test_insertion_sort()
    test_adjust_heap()
    test_introsort_loop()
    test_final_insertion_sort()
    test_sort_index()
    test_dedup()
    test_cleanable()
    test_release_tree()
    test_cache_teardown()
    test_build_iterator()
    test_host()
    print("%d tests passed" % CHECKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
