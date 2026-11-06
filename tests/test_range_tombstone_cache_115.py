"""Tests for tools/range_tombstone_cache_115.py.

Every expectation is grounded in the evidence packet
research/work-items/RE-001-range-tombstone-cache-115/: the excerpts,
the census, the catalogue's vendor attribution (MemTable::
NewRangeTombstoneIteratorInternal / FragmentedRangeTombstoneIterator
ctors / PhysicalCoreID / _M_release / Cleanable::DoCleanup) and the
re-derived picker/seed routines. Run:
    python3 tests/test_range_tombstone_cache_115.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from range_tombstone_cache_115 import (
    ATOMIC_FLAG_ADDR, CountedBase, Cleanable, Owner, ShardTable40,
    SlotObject, ThreadSeed, TombstoneCache, TombstoneList, TreeNode,
    atomic_rmw, cpuid_logical_count, iterator_from_cache,
    iterator_from_list, mersenne_step, pick_shard, release_tree,
    teardown_cache, _hash_bytes,
)


def check(name, cond):
    assert cond, name
    return 1


def _ref_mersenne_step(seed):
    """The host's seed-advance instruction sequence, followed
    literally: x = seed * 0x41a7 (64-bit); folded =
    (x & 0x7fffffff) + (x >> 31); subtract 0x7fffffff once when the
    sum is negative as a signed 32-bit value."""
    x = (seed * 0x41A7) & 0xFFFFFFFFFFFFFFFF
    folded = (x & 0x7FFFFFFF) + (x >> 31)
    if folded & 0x80000000:
        folded -= 0x7FFFFFFF
    return folded & 0xFFFFFFFF


def _owner(shift=3):
    return Owner(shift, 1 << shift)


def _cmp():
    return {"plus8": 0xCAFEBABE}


def main():
    n = 0

    # --- Picker 0x60d5cd0: cpuid leaf 0 -> -1; else EBX>>24.
    n += check("picker no leaf", cpuid_logical_count(0, 0) == -1)
    n += check("picker 8 cores", cpuid_logical_count(1, 0x08000000) == 8)
    n += check("picker 16 cores", cpuid_logical_count(7, 0x10000000) == 16)
    n += check("picker 1 core", cpuid_logical_count(13, 0x01000000) == 1)
    n += check("picker low bits ignored",
               cpuid_logical_count(7, 0x08FFFFFF) == 8)

    # --- Shard mask: source & ((1 << shift) - 1).
    n += check("shard exact", pick_shard(5, 3) == 5)
    n += check("shard wraps", pick_shard(9, 3) == 1)
    n += check("shard big", pick_shard(0x123, 4) == 3)
    n += check("shard shift 0", pick_shard(0x7FFFFFFF, 0) == 0)
    n += check("shard shift 4", pick_shard(0x7FFFFFFF, 4) == 15)

    # --- LCG seed step, against the literal instruction sequence.
    for seed in (0, 1, 2, 0x41A7, 0x12345678, 0x7FFFFFFE, 0x7FFFFFFF):
        n += check("step %#x" % seed,
                   mersenne_step(seed) == _ref_mersenne_step(seed))
    n += check("step 1", mersenne_step(1) == 0x41A7)
    n += check("step stays in range",
               all(0 < mersenne_step(s) <= 0x7FFFFFFF
                   for s in (1, 7, 12345, 0x7FFFFFFF)))
    n += check("step 0x7fffffff stays", mersenne_step(0x7FFFFFFF) == 0x7FFFFFFF)

    # --- ThreadSeed: first use hashes, then caches; 0 becomes 1.
    ts = ThreadSeed(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    first = ts.pointer()
    n += check("seed hashes tid",
               first == (_hash_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08",
                                     0xC70F6907) & 0x7FFFFFFF))
    n += check("seed cached", ts.pointer() == first)
    ts.store(0x41A7)
    n += check("seed stored", ts.pointer() == 0x41A7)
    ts2 = ThreadSeed(b"\x00" * 8)
    n += check("seed nonzero", ts2.pointer() != 0)

    # --- Atomicity selector at 0x64ed290.
    n += check("atomic flag addr", ATOMIC_FLAG_ADDR == 0x64ED290)
    n += check("atomic flag 0", atomic_rmw(0) is True)
    n += check("atomic flag 1", atomic_rmw(1) is False)

    # --- CountedBase 0x5d350c0: packed qword, add_ref, release.
    cb = CountedBase()
    n += check("counted fresh packed", cb.packed() == 0x100000001)
    n += check("counted release fast path disposes", cb.release() is True)
    n += check("counted fast path zeroes use", cb.use == 0)
    cb2 = CountedBase()
    cb2.add_ref()
    n += check("counted add_ref", cb2.use == 2)
    n += check("counted release no dispose", cb2.release() is False)
    n += check("counted release to 1", cb2.use == 1)
    n += check("counted second release disposes", cb2.release() is True)
    cb3 = CountedBase(use=1, weak=2)
    n += check("counted weak2 no fast path", cb3.release() is True)
    n += check("counted weak2 use 0", cb3.use == 0)
    cb4 = CountedBase(use=3, weak=1)
    n += check("counted use3 no dispose", cb4.release() is False)
    n += check("counted use3 to 2", cb4.use == 2)
    n += check("counted use3 second", cb4.release() is False)
    n += check("counted use3 third disposes", cb4.release() is True)

    # --- Cleanable 0x61bd0c0 / 0x61bd0e0.
    cl = Cleanable()
    n += check("cleanable empty", cl.do_cleanup() == [])
    cl.add("fn-a", 1, 2)
    cl.add("fn-b", 3, 4)
    calls = cl.do_cleanup()
    n += check("cleanable head first", calls[0] == ("fn-b", 3, 4))
    n += check("cleanable chain second", calls[1] == ("fn-a", 1, 2))
    n += check("cleanable drained", cl.do_cleanup() == [])

    # --- Node-tree release 0x5f059b0: child first, then node, then sibling.
    leaf = TreeNode("leaf")
    mid = TreeNode("mid", child=leaf)
    root = TreeNode("root", child=mid, sibling=TreeNode("sib"))
    n += check("tree release order",
               release_tree(root) == ["leaf", "mid", "root", "sib"])
    n += check("tree release null", release_tree(None) == [])
    single = TreeNode("only")
    n += check("tree release single", release_tree(single) == ["only"])

    # --- The 0x80-byte list the host builds.
    fields = {"field_10": "o10", "field_31": 1, "field_60": "o60",
              "field_6c": "o6c", "field_c58": "oc58",
              "vtable_slot_90": lambda: "slot90"}
    lst = TombstoneList(fields)
    n += check("list size", TombstoneList.SIZE == 0x80)
    n += check("list vtable", lst.vtable == 0x64CC638 + 0x10)
    n += check("list field 30", lst.field_30 == "oc58")
    n += check("list field 38", lst.field_38 == 0x64CC600 + 0x10)
    n += check("list field 40", lst.field_40 == 0x64C8FE8 + 0x10)
    n += check("list field 48", lst.field_48 == "o10")
    n += check("list field 50", lst.field_50 == "slot90")
    n += check("list field 5a flips", lst.field_5a == 0)
    n += check("list field 60", lst.field_60 == "o6c")
    n += check("list field 78", lst.field_78 == "o60")
    n += check("list field 28 zero", lst.field_28 == 0)
    n += check("list cleanable fresh", lst.cleanable.head is None)
    lst.destroy_via_slot1()
    n += check("list destroyed", lst.destroyed is True)

    # --- The 0xe8-byte cache built by 0x5f37410.
    entries = [("k1", 10), ("k2", 20), ("k3", 5)]
    cache = TombstoneCache(entries)
    n += check("cache size", TombstoneCache.SIZE == 0xE8)
    n += check("cache count", cache.count_d8 == 3)
    n += check("cache total", cache.total_size_e0 == 35)
    n += check("cache empty count", TombstoneCache([]).count_d8 == 0)
    n += check("cache empty total", TombstoneCache([]).total_size_e0 == 0)
    n += check("cache not finalized", cache.finalized is False)
    cache.finalize()
    n += check("cache finalized", cache.finalized is True)
    n += check("cache flag clear", cache.flag_b8 == 0)

    # --- Cache teardown order (host 0x5f0ac24..0x5f0ad26).
    old = TombstoneCache([("a", 1)])
    old.flag_b8 = 1
    old.index = ["e1", "e2"]
    old.list80 = ["n80"]
    old.list60 = [TreeNode("n60")]
    old.buffers = {"30": "b30", "18": "b18", "00": "b00"}
    old.cleanable.add("fn-x", 9, 9)
    steps = teardown_cache(old)
    n += check("teardown order", steps == [
        "array_fixup", "cleanup_chain", "delete_index_array",
        "do_cleanup_98", "free_list80_node", "release_list60_node",
        "free_buffer_30", "free_buffer_18", "free_buffer_00",
        "delete_cache"])
    n += check("teardown empties", old.index == [] and old.list80 == []
               and old.list60 == [] and old.flag_b8 == 0)
    old2 = TombstoneCache([])
    steps2 = teardown_cache(old2)
    n += check("teardown minimal", steps2 == ["do_cleanup_98",
                                               "delete_cache"])

    # --- Ctor A 0x5f31380 field layout.
    raw = {"plus8": "L+8", "plus18": "L+0x18"}
    cmp = _cmp()
    it_a = iterator_from_list(raw, cmp, 42, "slice", 7)
    n += check("ctorA vtable", it_a["vtable"] == 0x64CCAE0 + 0x10)
    n += check("ctorA cmp twice", it_a["field_28"] == 0xCAFEBABE
               and it_a["field_30"] == 0xCAFEBABE)
    n += check("ctorA cmp pair", it_a["field_38"] is cmp
               and it_a["field_40"] == 0xCAFEBABE)
    n += check("ctorA shared null", it_a["shared_ptr"] is None)
    n += check("ctorA list", it_a["field_68"] is raw)
    n += check("ctorA seq", it_a["field_70"] == 42)
    n += check("ctorA arg6", it_a["field_78"] == 7)
    n += check("ctorA slice", it_a["field_80"] == "slice")
    n += check("ctorA bounds", it_a["field_88"] == "L+8"
               and it_a["field_90"] == "L+0x18"
               and it_a["field_98"] == "L+8"
               and it_a["field_a0"] == "L+0x18")
    n += check("ctorA tail", it_a["field_a8"] == "self+0xb8"
               and it_a["field_b0"] == 0 and it_a["field_b8"] == 0)

    # --- Ctor B 0x5f315a0 field layout.
    obj = SlotObject()
    cache_b = TombstoneCache([("k", 3)])
    cache_b.bound_08 = "C+8"
    cache_b.bound_20 = "C+0x20"
    obj.cache = cache_b
    ctrl_b = CountedBase()
    shared = (obj, ctrl_b)
    it_b = iterator_from_cache(shared, cmp, 99, {"plus8": 5}, 11)
    n += check("ctorB vtable", it_b["vtable"] == 0x64CCAE0 + 0x10)
    n += check("ctorB shared copied", it_b["shared_ptr"] == shared)
    n += check("ctorB ctrl bumped", ctrl_b.use == 2)
    n += check("ctorB cache", it_b["field_68"] is cache_b)
    n += check("ctorB seq", it_b["field_70"] == 99)
    n += check("ctorB arg6", it_b["field_78"] == 11)
    n += check("ctorB slice kept", it_b["field_80"] == {"plus8": 5})
    n += check("ctorB bounds", it_b["field_88"] == "C+8"
               and it_b["field_90"] == "C+0x20"
               and it_b["field_98"] == "C+8"
               and it_b["field_a0"] == "C+0x20")
    it_b2 = iterator_from_cache(shared, cmp, 1, {"plus8": 0}, 0)
    n += check("ctorB empty slice null", it_b2["field_80"] is None)
    it_b3 = iterator_from_cache(shared, cmp, 1, None, 0)
    n += check("ctorB null slice null", it_b3["field_80"] is None)

    # --- Host end to end: flag path bypasses the slot.
    owner = _owner()
    it_f, tr_f = owner.new_range_tombstone_iterator_internal(
        [("k", 1)], 7, True, _cmp(), None, 0, 8, 0x08000000, b"\x00" * 8)
    n += check("flag path trace", tr_f == ["flag_path_ctor_a"])
    n += check("flag path no slot", all(s is None for s in owner.slots))
    n += check("flag path iterator", it_f["shared_ptr"] is None
               and it_f["field_70"] == 7)

    # --- Host end to end: first shard call builds, second reuses.
    owner2 = _owner()
    entries2 = [("a", 4), ("b", 6)]
    it1, tr1 = owner2.new_range_tombstone_iterator_internal(
        entries2, 3, False, _cmp(), None, 0, 8, 0x08000000, b"\x00" * 8)
    n += check("first call builds", tr1 == [
        "shard_0", "locker_claim", "mutex_lock", "build_list",
        "build_cache", "install_cache", "destroy_list",
        "set_ready_unlock", "release_claim_ref"])
    n += check("first call cache", it1["cache"] is not None
               and it1["cache"].count_d8 == 2
               and it1["cache"].total_size_e0 == 10)
    n += check("first call cache finalized", it1["cache"].finalized is True)
    slot0 = owner2.slots[0]
    n += check("first call slot ready", slot0[0].ready is True)
    n += check("first call use count", slot0[1].use == 2)
    it2, tr2 = owner2.new_range_tombstone_iterator_internal(
        entries2, 3, False, _cmp(), None, 0, 8, 0x08000000, b"\x00" * 8)
    n += check("second call reuses", tr2 == [
        "shard_0", "locker_claim", "ready_ctor_b", "release_claim_ref"])
    n += check("second call same cache", it2["cache"] is it1["cache"])
    n += check("second call use count", slot0[1].use == 3)

    # --- Host: a cache present but not ready takes the mutex path.
    owner3 = _owner()
    pre = TombstoneCache([("z", 9)])
    pre.finalize()
    obj3 = SlotObject()
    obj3.cache = pre
    owner3.slots[0] = (obj3, CountedBase())
    it3, tr3 = owner3.new_range_tombstone_iterator_internal(
        [], 1, False, _cmp(), None, 0, 8, 0x08000000, b"\x00" * 8)
    n += check("present cache trace", tr3 == [
        "shard_0", "locker_claim", "mutex_lock", "cache_present_ctor_b",
        "release_claim_ref"])
    n += check("present cache kept", it3["cache"] is pre)
    n += check("present cache unlocked", obj3.mutex_locked is False)

    # --- Host: picker -1 falls back to the advanced seed.
    owner4 = _owner()
    tid = b"\x10\x20\x30\x40\x50\x60\x70\x80"
    seed = ThreadSeed(tid)
    first_seed = seed.pointer()
    owner4.thread_seed = seed
    it4, tr4 = owner4.new_range_tombstone_iterator_internal(
        [("k", 1)], 1, False, _cmp(), None, 0, 0, 0, tid)
    want_idx = mersenne_step(first_seed) & 0x7
    n += check("seed fallback shard", tr4[0] == "shard_%d" % want_idx)
    n += check("seed advanced once",
               owner4.thread_seed.pointer() == mersenne_step(first_seed))

    # --- Shard helper 0x605e170: 0x40 stride, TLS record.
    st = ShardTable40(3, 8)
    slot_ptr, rec = st.shard_pointer(5, None, b"\x00" * 8)
    n += check("shard40 slot", slot_ptr == "slot5")
    n += check("shard40 tls record", rec == (5 | (1 << 3)))
    n += check("shard40 tls stored", st.tls_record == rec)
    slot_ptr2, rec2 = st.shard_pointer(13, None, b"\x00" * 8)
    n += check("shard40 masks", slot_ptr2 == "slot5" and rec2 == rec)
    seed40 = ThreadSeed(b"\x01" * 8)
    sv = seed40.pointer()
    slot_ptr3, rec3 = st.shard_pointer(-1, seed40, b"\x01" * 8)
    want3 = mersenne_step(sv) & 0x7
    n += check("shard40 seed fallback",
               slot_ptr3 == "slot%d" % want3
               and rec3 == (want3 | (1 << 3)))

    print("all %d tests passed" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
