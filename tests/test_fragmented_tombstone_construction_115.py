"""Tests for tools/fragmented_tombstone_construction_115.py.

Run from the repository root:
    python3 tests/test_fragmented_tombstone_construction_115.py

The probe gate and the split map are cross-checked against
independent linear-scan references on seeded random inputs.
"""

import random
import sys

sys.path.insert(0, "tools")
import fragmented_tombstone_construction_115 as m

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("FAIL: " + label)


ICMP = 0x1000  # fake InternalKeyComparator address


def make_list(seqs, frag_end=0x2000, seq_base=0x3000):
    return m.FragmentList(frag_end, seq_base, seqs)


def ref_probe(keys, lower, snapshot):
    """Independent linear reference for the probe gate: True iff the
    first key >= lower is >= snapshot (or no key >= lower means False
    when no key exists at all -- the binary returns False then)."""
    cands = [k for k in keys if k >= lower]
    if not cands:
        return False
    return min(cands) >= snapshot


def ref_split(keys, snapshots):
    """Independent linear reference for the split map keys."""
    out = []
    lower = 0
    for s in snapshots:
        if ref_probe(keys, lower, s) and s not in out:
            out.append(s)
        lower = s + 1
    return out


def main():
    # -- layout constants -------------------------------------------------
    check(m.ITERATOR_SIZE == 0xC8, "iterator is 0xc8 bytes")
    check(m.LIST_SIZE == 0xE8, "list is 0xe8 bytes")
    check(m.TRUNCATED_SIZE == 0x48, "truncated iterator is 0x48 bytes")
    check(m.VTABLE == 0x64CCAF0, "vtable slot 0 is 0x64ccaf0")
    check(m.PACKED_COUNTS == 0x100000001, "packed counts are 0x100000001")

    # -- ctor A: raw list ---------------------------------------------------
    fl = make_list([10, 20, 30])
    it = m.ctor_a(fl, ICMP, 100, "ub", 7)
    check(it[m.OFF_VTABLE] == m.VTABLE, "ctor A installs the vtable")
    check(it.list_holder is None, "ctor A leaves the List holder null")
    check(it.cache_holder is None, "ctor A leaves the Cache holder null")
    check(it[m.OFF_LIST_PTR] is fl, "ctor A stores the raw list at +0x68")
    check(it[m.OFF_READ_SEQ] == 100, "ctor A stores seq at +0x70")
    check(it.arg6 == 7, "ctor A stores arg6 at +0x78")
    check(it[m.OFF_UPPER_BOUND] == "ub", "ctor A stores the slice at +0x80")
    check(it[m.OFF_FRAG] == 0x2000, "ctor A copies list+0x08 to +0x88")
    check(it[0x98] == 0x2000, "ctor A shadows the frag pointer at +0x98")
    check(it[m.OFF_SEQ] == 0x3000, "ctor A copies list+0x18 to +0x90")
    check(it[0xA0] == 0x3000, "ctor A shadows the seq pointer at +0xa0")
    check(it[0x38] == ICMP, "ctor A stores icmp at +0x38")
    check(it[0x28] == ICMP + 0x8, "ctor A stores icmp+0x8 at +0x28")
    check(it[0x40] == ICMP + 0x8, "ctor A stores icmp+0x8 at +0x40")
    check(it[0xB0] == 0 and it[0xB8] == 0, "ctor A starts an empty key cache")

    # -- ctor List: shared_ptr<List> ----------------------------------------
    sp = m.SharedPtr(fl, ctrl=0x5000, use_count=3)
    it2 = m.ctor_list(sp, ICMP, 55, None, 0)
    check(it2.list_holder is fl, "ctor List copies the List ptr to +0x48")
    check(it2[m.OFF_LIST_HOLDER_CTRL] == 0x5000, "ctor List copies ctrl to +0x50")
    check(it2.holder_use_count == 4, "ctor List bumps the use count")
    check(it2.cache_holder is None, "ctor List leaves the Cache holder null")
    check(it2[m.OFF_LIST_PTR] is fl, "ctor List stores the list at +0x68")
    check(it2[m.OFF_FRAG] == 0x2000, "ctor List copies list+0x08 to +0x88")
    check(it2[m.OFF_SEQ] == 0x3000, "ctor List copies list+0x18 to +0x90")
    check(it2.arg6 == 0, "ctor List stores arg6 at +0x78")
    check(sp.use_count == 3, "ctor List does not mutate the source holder")

    # null shared_ptr: the bump is skipped, holders stay null-valued
    sp_null = m.SharedPtr(None, None, 0, 0)
    check(sp_null.copy().ptr is None, "null shared_ptr copy stays null")
    check(sp_null.release() == "noop", "null shared_ptr release is a no-op")

    # -- ctor Cache: shared_ptr<Cache> --------------------------------------
    cache = m.FragmentCache(frag_end=0x2100, seq_base=0x3100, list_ptr=fl)
    spc = m.SharedPtr(cache, ctrl=0x6000, use_count=1)
    it3 = m.ctor_cache(spc, ICMP, 77, "ub2", 9)
    check(it3.cache_holder is cache, "ctor Cache copies the Cache ptr to +0x58")
    check(it3[m.OFF_CACHE_HOLDER_CTRL] == 0x6000, "ctor Cache copies ctrl to +0x60")
    check(it3.holder_use_count == 2, "ctor Cache bumps the use count")
    check(it3.list_holder is None, "ctor Cache leaves the List holder null")
    check(it3[m.OFF_LIST_PTR] is fl, "ctor Cache stores cache+0x28 at +0x68")
    check(it3[m.OFF_FRAG] == 0x2100, "ctor Cache copies cache+0x08 to +0x88")
    check(it3[m.OFF_SEQ] == 0x3100, "ctor Cache copies cache+0x20 to +0x90")
    check(it3.arg6 == 9, "ctor Cache stores arg6 at +0x78")

    # the three ctors use distinct holder slots: no ctor writes both
    check(it.list_holder is None and it.cache_holder is None, "ctor A writes neither holder")
    check(it2.list_holder is not None and it2.cache_holder is None, "ctor List writes only the List holder")
    check(it3.list_holder is None and it3.cache_holder is not None, "ctor Cache writes only the Cache holder")

    # -- SharedPtr release ---------------------------------------------------
    check(m.SharedPtr(fl, 0x5000, 1, 1).release() == "dispose",
          "packed 0x100000001 releases with the fast dispose")
    check(m.SharedPtr(fl, 0x5000, 2, 1).release() == "decrement",
          "use_count 2 releases with a decrement")
    check(m.SharedPtr(fl, 0x5000, 1, 2).release() == "dispose",
          "use_count 1 with weak 2 still disposes")
    check(m.SharedPtr(fl, 0x5000, 1, 1).packed() == m.PACKED_COUNTS,
          "packed() matches the binary constant")

    # -- once-init: deduped sorted index --------------------------------------
    fl2 = make_list([30, 10, 20, 10, 30])
    idx = fl2.ensure_index()
    check(idx == [10, 20, 30], "once-init dedupes and sorts the seq array")
    check(fl2.index_count == 3, "once-init counts unique seqnums")
    check(fl2.ensure_index() is idx, "once-init is idempotent")
    fl_empty = make_list([])
    check(fl_empty.ensure_index() == [], "empty seq array gives an empty index")

    # -- probe gate: fixed cases ----------------------------------------------
    keys = [10, 20, 30]
    fl3 = make_list(keys)
    check(m.probe(fl3, 0, 5) is True, "no key in [0,5): probe true")
    check(m.probe(fl3, 0, 10) is True, "key == snapshot: probe true")
    check(m.probe(fl3, 0, 11) is False, "key 10 in [0,11): probe false")
    check(m.probe(fl3, 11, 25) is False, "key 20 in [11,25): probe false")
    check(m.probe(fl3, 21, 30) is True, "key 30 == snapshot: probe true")
    check(m.probe(fl3, 31, 100) is False, "no key >= lower: probe false")
    check(m.probe(fl_empty, 0, 5) is False, "empty index: probe false")
    check(m.probe(fl3, 10, 10) is True, "lower == key == snapshot: probe true")
    # cross-check the gate against the linear reference on random inputs
    rng = random.Random(0x5F33950)
    for _ in range(200):
        ks = sorted(rng.sample(range(0, 100), rng.randint(0, 12)))
        lo = rng.randint(0, 100)
        snap = rng.randint(0, 100)
        flr = make_list(ks)
        check(m.probe(flr, lo, snap) == ref_probe(ks, lo, snap),
              "probe matches the linear reference (keys=%r lo=%d snap=%d)" % (ks, lo, snap))

    # -- SplitBySnapshot --------------------------------------------------------
    fl4 = make_list([10, 20, 30])
    sm = m.split_by_snapshot(fl4, ICMP, [5, 15, 25, 35], "ub")
    # [0,5): no key -> create (arg6 0, seq 5); [6,15): key 10 -> skip;
    # [16,25): key 20 -> skip; [26,35): key 30 -> skip
    check(sorted(sm) == [5], "split map keys match the gate (case 1)")
    check(sm[5].read_seq == 5 and sm[5].arg6 == 0, "split iterator for 5 has seq 5 arg6 0")
    sm2 = m.split_by_snapshot(fl4, ICMP, [10, 20, 30], "ub")
    # [0,10): no key -> create; [11,20): no key -> create (arg6 11); [21,30): no key -> create (arg6 21)
    check(sorted(sm2) == [10, 20, 30], "split map keys match the gate (case 2)")
    check(sm2[20].arg6 == 11 and sm2[30].arg6 == 21, "arg6 advances to prev+1")
    check(sm2[10].arg6 == 0, "first split passes arg6 0")
    check(all(sm2[s][m.OFF_UPPER_BOUND] == "ub" for s in sm2), "upper bound is carried through")
    check(m.split_by_snapshot(fl4, ICMP, [], "ub") == {}, "no snapshots -> empty map")
    check(m.split_by_snapshot(fl_empty, ICMP, [1, 2, 3], "ub") == {}, "no keys -> empty map")
    # duplicate snapshot: first wins
    sm3 = m.split_by_snapshot(fl4, ICMP, [10, 10, 20], "ub")
    check(sorted(sm3) == [10, 20], "duplicate snapshot keeps the first iterator")
    # random cross-check of the split keys
    for _ in range(200):
        ks = sorted(rng.sample(range(0, 200), rng.randint(0, 15)))
        snaps = sorted(rng.sample(range(0, 200), rng.randint(0, 8)))
        flr = make_list(ks)
        got = sorted(m.split_by_snapshot(flr, ICMP, snaps, None))
        want = ref_split(ks, snaps)
        check(got == want, "split keys match the linear reference (keys=%r snaps=%r)" % (ks, snaps))

    # -- TruncatedRangeDelIterator consumer --------------------------------------
    inner = {5: "it5", 20: "it20"}
    outer = m.truncated_split_by_snapshot(inner, {"a": 1})
    check(sorted(outer) == [5, 20], "wrapper preserves the snapshot keys")
    check(outer[5]["wrapped_iterator"] == "it5", "wrapper keeps the split iterator")
    check(outer[20]["outer_fields"] == {"a": 1}, "wrapper carries the outer fields")

    # -- BlockBasedTable::NewRangeTombstoneIterator ------------------------------
    check(m.block_table_new_iterator(None, ICMP, 42, "ub") is None,
          "null list -> null iterator")
    check(m.block_table_new_iterator(m.SharedPtr(None, None, 0, 0), ICMP, 42, "ub") is None,
          "null shared_ptr -> null iterator")
    spb = m.SharedPtr(fl, ctrl=0x7000, use_count=2)
    itb = m.block_table_new_iterator(spb, ICMP, 42, "ub")
    check(itb is not None and itb.read_seq == 42, "table path passes the snapshot as seq")
    check(itb.arg6 == 0, "table path passes arg6 0")
    check(itb[m.OFF_UPPER_BOUND] == "ub", "table path passes ReadOptions+0x58 as the slice")
    check(itb.list_holder is fl, "table path builds via ctor List")
    itb2 = m.block_table_new_iterator(spb, ICMP, None, "ub")
    check(itb2.read_seq == m.MAX_SEQNUM, "absent snapshot passes seq -1")

    # -- CompactionRangeDelAggregator::NewIterator --------------------------------
    itc = m.compaction_new_iterator(fl, ICMP)
    check(itc.read_seq == m.MAX_SEQNUM, "compaction path passes seq -1")
    check(itc.arg6 == 0, "compaction path passes arg6 0")
    check(itc[m.OFF_UPPER_BOUND] is None, "compaction path passes a null slice")
    check(itc.list_holder is fl, "compaction path builds via ctor List")

    print("%d tests passed" % CHECKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
