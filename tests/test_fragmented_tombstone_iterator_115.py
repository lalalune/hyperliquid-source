"""Tests for tools/fragmented_tombstone_iterator_115.py.

Run from the repository root:
    python3 tests/test_fragmented_tombstone_iterator_115.py

The binary-search helpers and the seek/scan flows are cross-checked
against independent linear-scan references on seeded random inputs.
"""

import random
import sys

sys.path.insert(0, "tools")
import fragmented_tombstone_iterator_115 as m

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("FAIL: " + label)


def make_list(specs, seqs, keys=None):
    """specs: [(start, end, begin, end), ...]; seqs: the seq array;
    keys: the key array (defaults to one b'k%02d' entry per seq)."""
    frags = [m.Fragment(s, e, b, en) for (s, e, b, en) in specs]
    if keys is None:
        keys = [b"k%02d" % i for i in range(len(seqs))]
    return m.FragmentList(frags, seqs, keys)


def ref_first_seq_le(seqs, read_seq, begin, end):
    for i in range(begin, end):
        if seqs[i] <= read_seq:
            return i
    return end


def ref_first_frag_end_gt(frags, key, cmp):
    for i, f in enumerate(frags):
        if cmp(key, f.end) < 0:
            return i
    return len(frags)


def ref_first_frag_start_gt(frags, key, cmp):
    for i, f in enumerate(frags):
        if cmp(key, f.start) < 0:
            return i
    return len(frags)


def ref_seek(fl, cmp, read_seq, arg6, key):
    """Independent linear-scan reference for seek(key): the covering
    fragment, the first seq <= read_seq, then the forward scan."""
    j = ref_first_frag_end_gt(fl.fragments, key, cmp)
    if j >= len(fl.fragments):
        return (None, len(fl.seqnums))
    frag = fl.fragments[j]
    s = ref_first_seq_le(fl.seqnums, read_seq, frag.seq_begin, frag.seq_end)
    pos = (j, s)
    while True:
        f, s = pos
        if f is None:
            return pos
        frag = fl.fragments[f]
        if s == frag.seq_end:
            if f + 1 >= len(fl.fragments):
                return (None, len(fl.seqnums))
            f += 1
            frag = fl.fragments[f]
            s = ref_first_seq_le(fl.seqnums, read_seq, frag.seq_begin, frag.seq_end)
            pos = (f, s)
            continue
        if fl.seqnums[s] >= arg6:
            return pos
        if f + 1 >= len(fl.fragments):
            return (None, len(fl.seqnums))
        f += 1
        frag = fl.fragments[f]
        s = ref_first_seq_le(fl.seqnums, read_seq, frag.seq_begin, frag.seq_end)
        pos = (f, s)


def ref_seek_for_prev(fl, cmp, read_seq, arg6, key):
    j = ref_first_frag_start_gt(fl.fragments, key, cmp)
    if len(fl.fragments) == 0:
        return (None, len(fl.seqnums))
    if j == 0:
        return (None, 0)
    f = j - 1
    frag = fl.fragments[f]
    s = ref_first_seq_le(fl.seqnums, read_seq, frag.seq_begin, frag.seq_end)
    pos = (f, s)
    while True:
        f, s = pos
        if f is None:
            return pos
        frag = fl.fragments[f]
        if s == frag.seq_end:
            if f == 0:
                return (None, len(fl.seqnums))
            f -= 1
            frag = fl.fragments[f]
            s = ref_first_seq_le(fl.seqnums, read_seq, frag.seq_begin, frag.seq_end)
            pos = (f, s)
            continue
        if fl.seqnums[s] >= arg6:
            return pos
        if f == 0:
            return (None, len(fl.seqnums))
        f -= 1
        frag = fl.fragments[f]
        s = ref_first_seq_le(fl.seqnums, read_seq, frag.seq_begin, frag.seq_end)
        pos = (f, s)


def main():
    bw = m.BytewiseComparator()
    rv = m.ReverseBytewiseComparator()
    ts = m.TimestampedComparator()

    # -- memcmp / reverse ordering --------------------------------------
    check(m.memcmp(b"a", b"b") < 0, "memcmp a<b")
    check(m.memcmp(b"b", b"a") > 0, "memcmp b>a")
    check(m.memcmp(b"ab", b"ab") == 0, "memcmp equal")
    check(m.memcmp(b"ab", b"abc") < 0, "memcmp prefix shorter is smaller")
    check(m.memcmp(b"abc", b"ab") > 0, "memcmp prefix longer is larger")
    check(m.memcmp(b"", b"a") < 0, "memcmp empty < non-empty")
    check(m.reverse_memcmp(b"a", b"b") > 0, "reverse a>b")
    check(m.reverse_memcmp(b"ab", b"abc") > 0, "reverse prefix longer is smaller")
    check(m.reverse_memcmp(b"abc", b"ab") < 0, "reverse prefix shorter is larger")
    check(m.reverse_memcmp(b"ab", b"ab") == 0, "reverse equal")

    # -- comparator slots -------------------------------------------------
    check(bw.compare_timestamp(b"x", b"y") == 0, "bytewise slot25 returns 0")
    check(rv.compare_timestamp(b"x", b"y") == 0, "reverse slot25 returns 0")
    check(ts.compare_timestamp(b"x", b"y") < 0, "timestamped slot25 orders")
    check(bw.compare_without_timestamp(b"a", b"b") < 0, "bytewise slot26 memcmp")
    check(rv.compare_without_timestamp(b"a", b"b") > 0, "reverse slot26 negated")
    check(ts.compare_without_timestamp(b"a", b"b") < 0, "timestamped slot26 memcmp")

    # -- fragment list validation -----------------------------------------
    fl = make_list([(b"a", b"c", 0, 2), (b"c", b"e", 2, 4)], [30, 20, 25, 15])
    check(len(fl.fragments) == 2, "list has 2 fragments")
    try:
        make_list([(b"a", b"c", 0, 2)], [10, 20])
        check(False, "ascending seqnums must fail validation")
    except AssertionError as e:
        check("descend" in str(e), "ascending seqnums raise")

    # -- descending-seqnum search vs linear scan --------------------------
    rng = random.Random(0x5F32900)
    for trial in range(20):
        n = rng.randrange(0, 12)
        seqs = sorted((rng.randrange(0, 100) for _ in range(n)), reverse=True)
        fl2 = make_list([], seqs) if n == 0 else make_list(
            [(b"a", b"z", 0, n)], seqs)
        it = m.FragmentedRangeTombstoneIterator(fl2, bw, read_seq=0)
        read = rng.randrange(0, 110)
        it.read_seq = read
        got = it._first_seq_le(0, n)
        want = ref_first_seq_le(seqs, read, 0, n)
        check(got == want, "first_seq_le trial %d (read %d)" % (trial, read))
    it = m.FragmentedRangeTombstoneIterator(
        make_list([(b"a", b"z", 0, 3)], [50, 40, 30]), bw, 40)
    check(it._first_seq_le(0, 3) == 1, "first_seq_le exact match")
    check(it._first_seq_le(0, 0) == 0, "first_seq_le empty range")
    it.read_seq = 100
    check(it._first_seq_le(0, 3) == 0, "first_seq_le all below read")
    it.read_seq = 10
    check(it._first_seq_le(0, 3) == 3, "first_seq_le all above read")

    # -- fragment binary searches vs linear scan --------------------------
    for trial in range(20):
        nfrag = rng.randrange(1, 6)
        starts = sorted(rng.sample([b"a", b"b", b"c", b"d", b"e", b"f"], nfrag))
        specs = []
        seqs = []
        for i, s in enumerate(starts):
            e = chr(ord(s.decode()) + 1).encode()
            n = rng.randrange(1, 4)
            base = len(seqs)
            seqs.extend(sorted((rng.randrange(0, 100) for _ in range(n)), reverse=True))
            specs.append((s, e, base, base + n))
        fl3 = make_list(specs, seqs)
        it3 = m.FragmentedRangeTombstoneIterator(fl3, bw, 50)
        key = bytes([rng.randrange(ord("a"), ord("g"))])
        check(it3._first_frag_end_gt(key) == ref_first_frag_end_gt(
            fl3.fragments, key, bw.compare_without_timestamp),
            "first_frag_end_gt trial %d" % trial)
        check(it3._first_frag_start_gt(key) == ref_first_frag_start_gt(
            fl3.fragments, key, bw.compare_without_timestamp),
            "first_frag_start_gt trial %d" % trial)

    # -- the upper-bound clamp ---------------------------------------------
    # The binary's search goes left when the comparison is <= 0 and
    # right when it is > 0, so it assumes the key array is sorted
    # with the comparison decreasing in the entry index: the tests
    # use descending keys, and consumed is the first index whose
    # comparison is <= 0.
    fl4 = make_list([(b"a", b"z", 0, 3)], [50, 40, 30],
                    keys=[b"o", b"p", b"m"])
    it4 = m.FragmentedRangeTombstoneIterator(fl4, bw, 100, upper_bound=b"z")
    it4.frag, it4.seq_idx = 0, 0
    it4._clamp(0)
    check(it4.seq_idx == 0, "builtin clamp is a no-op (slot25 returns 0)")
    it4b = m.FragmentedRangeTombstoneIterator(fl4, ts, 100, upper_bound=b"n")
    it4b.frag, it4b.seq_idx = 0, 0
    it4b._clamp(0)
    check(it4b.seq_idx == 2, "timestamped clamp cuts to the first key <= ub")
    it4c = m.FragmentedRangeTombstoneIterator(fl4, ts, 100, upper_bound=b"a")
    it4c.frag, it4c.seq_idx = 0, 2
    it4c._clamp(0)
    check(it4c.seq_idx == 3, "timestamped clamp with all keys > ub cuts to the range end")
    it4f = m.FragmentedRangeTombstoneIterator(fl4, ts, 100, upper_bound=b"z")
    it4f.frag, it4f.seq_idx = 0, 1
    it4f._clamp(0)
    check(it4f.seq_idx == 1, "timestamped clamp with all keys <= ub: consumed 0, no clamp")
    it4d = m.FragmentedRangeTombstoneIterator(fl4, ts, 100, upper_bound=None)
    it4d.frag, it4d.seq_idx = 0, 0
    it4d._clamp(0)
    check(it4d.seq_idx == 0, "null upper bound: no clamp")
    it4e = m.FragmentedRangeTombstoneIterator(fl4, ts, 100, upper_bound=b"")
    it4e.frag, it4e.seq_idx = 0, 0
    it4e._clamp(0)
    check(it4e.seq_idx == 0, "empty upper bound: no clamp")
    # Randomized cross-check: on descending key arrays the binary
    # search returns the first index whose comparison is <= 0.
    for trial in range(15):
        n = rng.randrange(1, 8)
        keys = sorted((bytes([rng.randrange(ord("a"), ord("z") + 1)])
                       for _ in range(n)), reverse=True)
        seqs = sorted((rng.randrange(0, 100) for _ in range(n)), reverse=True)
        flr = make_list([(b"a", b"z", 0, n)], seqs, keys=keys)
        ub = bytes([rng.randrange(ord("a"), ord("z") + 1)])
        itr = m.FragmentedRangeTombstoneIterator(flr, ts, 100, upper_bound=ub)
        start = rng.randrange(0, n)
        itr.frag, itr.seq_idx = 0, start
        itr._clamp(0)
        first_le = next((i for i, k in enumerate(keys)
                         if m.memcmp(k, ub) <= 0), n)
        want = first_le if start < first_le else start
        check(itr.seq_idx == want,
              "clamp trial %d keys=%r ub=%r start=%d" % (trial, keys, ub, start))

    # -- seek_to_covering_tombstone -----------------------------------------
    it5 = m.FragmentedRangeTombstoneIterator(
        make_list([], []), bw, 50)
    it5.seek_to_covering_tombstone(b"a")
    check(it5.frag is None and it5.seq_idx == 0, "covering on empty list is (end, seq_end)")
    fl5 = make_list([(b"b", b"d", 0, 2), (b"d", b"f", 2, 3)], [30, 20, 25])
    it5 = m.FragmentedRangeTombstoneIterator(fl5, bw, 25)
    it5.seek_to_covering_tombstone(b"c")
    check((it5.frag, it5.seq_idx) == (0, 1), "covering finds first frag with end>key and first seq<=read")
    it5.seek_to_covering_tombstone(b"z")
    check(it5.frag is None and it5.seq_idx == 3, "covering past the last frag is the end")
    it5.seek_to_covering_tombstone(b"a")
    check((it5.frag, it5.seq_idx) == (0, 1), "covering before the first frag is frag 0, first seq<=read")
    it5b = m.FragmentedRangeTombstoneIterator(fl5, bw, 5)
    it5b.seek_to_covering_tombstone(b"c")
    check((it5b.frag, it5b.seq_idx) == (0, 2), "all seqs above read -> range end")

    # -- seek_for_prev_to_covering_tombstone ---------------------------------
    it6 = m.FragmentedRangeTombstoneIterator(fl5, bw, 25)
    it6.seek_for_prev_to_covering_tombstone(b"e")
    check((it6.frag, it6.seq_idx) == (1, 2), "seekforprev lands on the last frag starting <= key")
    it6.seek_for_prev_to_covering_tombstone(b"a")
    check(it6.frag is None and it6.seq_idx == 0, "seekforprev with no covering frag is (end, seq_base)")
    it6b = m.FragmentedRangeTombstoneIterator(make_list([], []), bw, 25)
    it6b.seek_for_prev_to_covering_tombstone(b"a")
    check(it6b.frag is None and it6b.seq_idx == 0, "seekforprev on empty list is (end, seq_end=0)")

    # -- seek / seek_for_prev vs the linear reference -------------------------
    for trial in range(30):
        nfrag = rng.randrange(1, 6)
        starts = sorted(rng.sample([b"a", b"b", b"c", b"d", b"e", b"f"], nfrag))
        specs, seqs = [], []
        for s in starts:
            e = chr(ord(s.decode()) + 1).encode()
            n = rng.randrange(1, 4)
            base = len(seqs)
            seqs.extend(sorted((rng.randrange(0, 100) for _ in range(n)), reverse=True))
            specs.append((s, e, base, base + n))
        flr = make_list(specs, seqs)
        read = rng.randrange(0, 110)
        arg6 = rng.randrange(0, 110)
        key = bytes([rng.randrange(ord("a"), ord("g"))])
        itr = m.FragmentedRangeTombstoneIterator(flr, bw, read, arg6=arg6)
        itr.seek(key)
        want = ref_seek(flr, bw.compare_without_timestamp, read, arg6, key)
        check((itr.frag, itr.seq_idx) == want,
              "seek trial %d key=%r read=%d arg6=%d" % (trial, key, read, arg6))
        itr2 = m.FragmentedRangeTombstoneIterator(flr, bw, read, arg6=arg6)
        itr2.seek_for_prev(key)
        want2 = ref_seek_for_prev(flr, bw.compare_without_timestamp, read, arg6, key)
        check((itr2.frag, itr2.seq_idx) == want2,
              "seek_for_prev trial %d key=%r read=%d arg6=%d" % (trial, key, read, arg6))

    # -- scan visibility (arg6) ------------------------------------------------
    fl6 = make_list([(b"a", b"c", 0, 2), (b"c", b"e", 2, 4)], [30, 20, 25, 15])
    it7 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=25)
    it7.frag, it7.seq_idx = 0, 1  # seq 20 < arg6 25: not visible
    it7.scan_forward_to_visible_tombstone()
    check((it7.frag, it7.seq_idx) == (1, 2), "scan forward skips seq < arg6")
    it7b = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=20)
    it7b.frag, it7b.seq_idx = 0, 1  # seq 20 >= arg6 20: visible
    it7b.scan_forward_to_visible_tombstone()
    check((it7b.frag, it7b.seq_idx) == (0, 1), "scan forward stops at seq >= arg6")
    it7c = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=100)
    it7c.frag, it7c.seq_idx = 0, 0
    it7c.scan_forward_to_visible_tombstone()
    check(it7c.frag is None, "scan forward past the end when nothing is visible")
    it7d = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=25)
    it7d.frag, it7d.seq_idx = 1, 3  # seq 15 < 25: step back
    it7d.scan_backward_to_visible_tombstone()
    check((it7d.frag, it7d.seq_idx) == (0, 0), "scan backward skips seq < arg6")
    it7e = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=15)
    it7e.frag, it7e.seq_idx = 1, 3
    it7e.scan_backward_to_visible_tombstone()
    check((it7e.frag, it7e.seq_idx) == (1, 3), "scan backward stops at seq >= arg6")

    # -- seek_to_top_first / last, top_next / top_prev -------------------------
    it8 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    it8.seek_to_top_first()
    check((it8.frag, it8.seq_idx) == (0, 0), "seek_to_top_first lands on frag 0")
    it8.top_next()
    check((it8.frag, it8.seq_idx) == (1, 2), "top_next advances one fragment")
    it8.top_next()
    check(it8.frag is None, "top_next at the last fragment reaches the end")
    it8b = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    it8b.seek_to_top_last()
    check((it8b.frag, it8b.seq_idx) == (1, 2), "seek_to_top_last lands on the last frag")
    it8b.top_prev()
    check((it8b.frag, it8b.seq_idx) == (0, 0), "top_prev steps back one fragment")
    it8b.top_prev()
    check(it8b.frag is None and it8b.seq_idx == 0, "top_prev at the first frag is (end, seq_base)")
    it8c = m.FragmentedRangeTombstoneIterator(make_list([], []), bw, 100)
    it8c.seek_to_top_first()
    check(it8c.frag is None, "seek_to_top_first on empty list is the end")
    it8c.seek_to_top_last()
    check(it8c.frag is None, "seek_to_top_last on empty list is the end")

    # -- next / prev -------------------------------------------------------------
    it9 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    it9.seek_to_first()
    check((it9.frag, it9.seq_idx) == (0, 0), "seek_to_first is (frag 0, seq base)")
    it9.next()
    check((it9.frag, it9.seq_idx) == (0, 1), "next steps within the fragment")
    it9.next()
    check((it9.frag, it9.seq_idx) == (1, 2), "next crosses the fragment boundary")
    it9.next()
    check((it9.frag, it9.seq_idx) == (1, 3), "next steps within the last fragment")
    it9.next()
    check(it9.frag is None and it9.seq_idx == 4, "next past the last seq reaches the end")
    it9.prev()
    check((it9.frag, it9.seq_idx) == (1, 3), "prev from the end returns to the last seq")
    it9.prev()
    check((it9.frag, it9.seq_idx) == (1, 2), "prev steps within the fragment")
    it9.prev()
    check((it9.frag, it9.seq_idx) == (0, 1), "prev crosses back over the boundary")
    it9.prev()
    it9.prev()
    check(it9.frag is None and it9.seq_idx == 4, "prev at the array base is (end, seq_end)")
    it9b = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    it9b.seek_to_last()
    check((it9b.frag, it9b.seq_idx) == (1, 3), "seek_to_last is the last seqnum")

    # -- key() / value() / slot11 / status / next_and_get_result -------------------
    it10 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    check(it10.key() == b"", "key() on a fresh iterator is empty")
    it10.seek_to_first()
    k = it10.key()
    check(k == b"a" + m.pack_sequence_and_type(30, 0x0F), "key() is start key + (seq<<8|0x0f)")
    check(it10.key() == k, "key() returns the cached key on repeat")
    check(it10.value() == b"c", "value() is the fragment end key")
    check(it10.slot11_user_key() == b"a", "slot11 is key() minus the 8-byte trailer")
    check(it10.status() == "OK", "status() is OK")
    it10.next()
    k2 = it10.key()
    check(k2 == b"a" + m.pack_sequence_and_type(20, 0x0F), "key() rebuilds after Next (shadow stale)")
    it10.seek(b"z")
    check(it10.key() == k2, "key() at the end returns the stale cached key")
    it11 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    it11.seek_to_first()
    res = it11.next_and_get_result()
    check(res["valid"] is True, "next_and_get_result is valid after one Next")
    check(res["key"] == b"a" + m.pack_sequence_and_type(20, 0x0F), "next_and_get_result returns the next key")
    check(res["extra_u16"] == 0, "next_and_get_result stores u16 0 at +0x10")
    it11b = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, arg6=0)
    it11b.seek_to_last()
    res2 = it11b.next_and_get_result()
    check(res2["valid"] is False and res2["key"] is None, "next_and_get_result past the end is invalid")

    # -- max_covering_tombstone_seqnum ----------------------------------------------
    it12 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100)
    check(it12.max_covering_tombstone_seqnum(b"b") == 30, "maxseq returns the covering seqnum")
    it12b = m.FragmentedRangeTombstoneIterator(fl6, bw, 25)
    check(it12b.max_covering_tombstone_seqnum(b"z") == 0, "maxseq past the last frag is 0")
    it12c = m.FragmentedRangeTombstoneIterator(fl6, bw, 5)
    check(it12c.max_covering_tombstone_seqnum(b"b") == 0, "maxseq with all seqs above read is 0")
    fl_gap = make_list([(b"d", b"f", 0, 1)], [30])
    it12d = m.FragmentedRangeTombstoneIterator(fl_gap, bw, 100)
    check(it12d.max_covering_tombstone_seqnum(b"a") == 0, "maxseq with frag start > key is 0")
    check(it12d.max_covering_tombstone_seqnum(b"e") == 30, "maxseq inside the frag returns the seqnum")

    # -- destructor ------------------------------------------------------------------
    cache = m.SharedPtr("cache")
    cache.use = 2
    second = m.SharedPtr("second")
    it13 = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, cache_ptr=cache, second_ptr=second)
    it13.seek_to_first()
    it13.key()  # short key: inline buffer
    trace = it13.destroy()
    check(trace == ["reset_vtable", "decrement('cache' -> 1)",
                    "dispose('second')", "reset_base_vtable",
                    "cleanable_do_cleanup"],
          "D1 trace: cache decremented, second disposed, no delete")
    check(cache.use == 1 and second.disposed, "D1 shared_ptr counts")
    it13b = m.FragmentedRangeTombstoneIterator(fl6, bw, 100, cache_ptr=m.SharedPtr("c2"))
    it13b.seek_to_first()
    trace_b = it13b.destroy(delete_self=True)
    check(trace_b[-1] == "operator_delete_this_0xc8", "D0 ends with operator delete(this, 0xc8)")
    check("free_key_cache_heap" not in trace_b, "short cached key stays inline")
    long_fl = make_list([(b"a" * 20, b"z" * 20, 0, 1)], [30])
    it13c = m.FragmentedRangeTombstoneIterator(long_fl, bw, 100)
    it13c.seek_to_first()
    it13c.key()
    check(it13c.key_cache_is_heap(), "a 20-byte start key makes the cache heap-allocated")
    trace_c = it13c.destroy()
    check("free_key_cache_heap" in trace_c, "D1 frees the heap key cache")

    # -- layout constants ---------------------------------------------------------------
    check(m.TYPE_RANGE_DELETION == 0x0F, "kTypeRangeDeletion is 0x0f")
    check(m.pack_sequence_and_type(0x1234, 0x0F) == bytes.fromhex("0f34120000000000"),
          "PackSequenceAndType is (seq<<8|type) little-endian")

    print("%d tests passed" % CHECKS[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
