"""Python model of node #115's FragmentedRangeTombstoneIterator (RE-001).

Faithful model of the 33 windows in
research/work-items/RE-001-fragmented-tombstone-iterator-115/:
the whole iterator method family (seek/scan/top/max-seqnum/valid/
next/prev/key/value/status/destructors) over a fragment list, with
the comparator dispatch (slot 0xc8 CompareTimestamp, slot 0xd0
CompareWithoutTimestamp), the descending-seqnum search, the
upper-bound clamp, the two end-position variants and the key() cache
invalidation via the +0x98/+0xa0 shadow. Positions are (frag_index,
seq_index); frag_index None means the fragment pointer is the list
end. The seq index distinguishes the two end variants: seq_end
(len(seqnums)) vs seq_base (0).

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
"""

# --- comparators -------------------------------------------------------

def memcmp(a, b):
    """Unsigned lexicographic byte compare, like C memcmp."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return -1 if a[i] < b[i] else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def reverse_memcmp(a, b):
    """Negated memcmp with a reversed length tiebreak (the Reverse
    Bytewise comparator: the longer of two prefix-related keys is the
    smaller one)."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return 1 if a[i] < b[i] else -1
    if len(a) == len(b):
        return 0
    return -1 if len(a) > len(b) else 1


class BytewiseComparator:
    """The builtin bytewise comparator: slot 0xd0 is plain memcmp,
    slot 0xc8 (CompareTimestamp) always returns 0. The binary
    short-circuits the upper-bound clamp when the slot-0xc8 function
    pointer is this builtin (consumed = 0, no clamp)."""

    timestamp_is_builtin = True

    def compare_without_timestamp(self, a, b):
        return memcmp(a, b)

    def compare_timestamp(self, a, b):
        return 0


class ReverseBytewiseComparator:
    """The builtin reverse-bytewise comparator: slot 0xd0 is the
    negated memcmp, slot 0xc8 always returns 0."""

    timestamp_is_builtin = True

    def compare_without_timestamp(self, a, b):
        return reverse_memcmp(a, b)

    def compare_timestamp(self, a, b):
        return 0


class TimestampedComparator:
    """A comparator with a real slot-0xc8 ordering (used by the tests
    to make the upper-bound clamp fire; the builtin comparators make
    it a no-op)."""

    timestamp_is_builtin = False

    def compare_without_timestamp(self, a, b):
        return memcmp(a, b)

    def compare_timestamp(self, a, b):
        return memcmp(a, b)


# --- structures --------------------------------------------------------

class Fragment:
    """One 0x30-byte fragment: start/end keys and the seqnum range."""

    def __init__(self, start, end, seq_begin, seq_end):
        self.start = start
        self.end = end
        self.seq_begin = seq_begin
        self.seq_end = seq_end

    def __repr__(self):
        return "Fragment(%r, %r, %d, %d)" % (
            self.start, self.end, self.seq_begin, self.seq_end)


class FragmentList:
    """The list at this+0x68: fragments, the seq array (descending
    within each fragment's range) and the parallel key array (16-byte
    Slice entries, one per seqnum index)."""

    def __init__(self, fragments, seqnums, keys):
        self.fragments = list(fragments)
        self.seqnums = list(seqnums)
        self.keys = list(keys)
        assert len(self.keys) == len(self.seqnums)
        for f in self.fragments:
            assert 0 <= f.seq_begin <= f.seq_end <= len(self.seqnums)
            for i in range(f.seq_begin, f.seq_end - 1):
                assert self.seqnums[i] >= self.seqnums[i + 1], (
                    "seqnums must descend within a fragment range")

    def __len__(self):
        return len(self.fragments)


class SharedPtr:
    """A minimal shared_ptr (ptr + control block with a use count)
    for the destructor model."""

    def __init__(self, obj):
        self.obj = obj
        self.use = 1
        self.disposed = False

    def release(self, trace):
        """_M_release: the packed (use=1, weak=1) fast path disposes
        at once; otherwise the count decrements and dispose runs when
        it reaches 0."""
        if self.use == 1:
            self.use = 0
            self.disposed = True
            trace.append("dispose(%r)" % (self.obj,))
            return True
        self.use -= 1
        if self.use == 0:
            self.disposed = True
            trace.append("dispose(%r)" % (self.obj,))
            return True
        trace.append("decrement(%r -> %d)" % (self.obj, self.use))
        return False


# --- the iterator ------------------------------------------------------

TYPE_RANGE_DELETION = 0x0F


def pack_sequence_and_type(seq, typ):
    """PackSequenceAndType: (seq << 8) | type, little-endian u64."""
    return ((seq << 8) | typ).to_bytes(8, "little")


class FragmentedRangeTombstoneIterator:
    """The 0xc8-byte iterator. `frag` is a fragment index or None
    (the fragment pointer is the list end); `seq_idx` is an index
    into the seq array. The shadow (+0x98/+0xa0) records the position
    at which key() was last built."""

    def __init__(self, frag_list, comparator, read_seq, upper_bound=None,
                 arg6=0, from_cache=False, cache_ptr=None, second_ptr=None):
        self.frag_list = frag_list
        self.comparator = comparator
        self.read_seq = read_seq
        self.upper_bound = upper_bound
        self.arg6 = arg6
        self.cache_ptr = cache_ptr
        self.second_ptr = second_ptr
        # Ctor A (raw list): frag = frag end, seq = seq base.
        # Ctor B (cache): frag = frag end, seq = seq end.
        self.frag = None
        self.seq_idx = len(frag_list.seqnums) if from_cache else 0
        self.shadow_frag = self.frag
        self.shadow_seq_idx = self.seq_idx
        self.cached_key = b""
        self.destroyed = False

    # -- position helpers ------------------------------------------------

    def _set_end(self, seq_idx, update_shadow=False):
        self.frag = None
        self.seq_idx = seq_idx
        if update_shadow:
            self.shadow_frag = None
            self.shadow_seq_idx = seq_idx

    def _first_seq_le(self, begin, end):
        """The descending-seqnum binary search: the first index in
        [begin, end) with seqnums[i] <= read_seq, or end. Mirrors the
        binary's loop (go left when read_seq >= *mid, else right)."""
        seqs = self.frag_list.seqnums
        lo = begin
        n = end - begin
        while n > 0:
            half = n // 2
            mid = lo + half
            if self.read_seq >= seqs[mid]:
                n = half
            else:
                lo = mid + 1
                n = n - half - 1
        return lo

    def _first_frag_end_gt(self, key):
        """The first fragment with end_key > key (binary search via
        slot 0xd0), or len(fragments)."""
        frags = self.frag_list.fragments
        lo = 0
        n = len(frags)
        cmp = self.comparator.compare_without_timestamp
        while n > 0:
            half = n // 2
            mid = lo + half
            if cmp(key, frags[mid].end) < 0:
                n = half
            else:
                lo = mid + 1
                n = n - half - 1
        return lo

    def _first_frag_start_gt(self, key):
        """The first fragment with start_key > key (binary search via
        slot 0xd0), or len(fragments)."""
        frags = self.frag_list.fragments
        lo = 0
        n = len(frags)
        cmp = self.comparator.compare_without_timestamp
        while n > 0:
            half = n // 2
            mid = lo + half
            if cmp(key, frags[mid].start) < 0:
                n = half
            else:
                lo = mid + 1
                n = n - half - 1
        return lo

    def _clamp(self, frag_idx):
        """The upper-bound clamp: binary-search the key array over
        the fragment's range for the first entry with
        CompareTimestamp(entry, upper_bound) <= 0, and cut the seq
        window at that index when the current offset is below it.
        The loop mirrors the binary exactly: mid = base + (n/2);
        when the comparison is <= 0 the left half is kept (n = half),
        when it is > 0 the base advances past mid (lo = mid + 1) —
        so the search assumes the key array is sorted with the
        comparison decreasing in the entry index. No-op when there
        is no upper bound (null or empty slice), and no-op when the
        slot-0xc8 implementation is the builtin ret-0 function: the
        binary short-circuits the search in that case (consumed = 0),
        so the clamp never fires."""
        if self.upper_bound is None or len(self.upper_bound) == 0:
            return
        if getattr(self.comparator, "timestamp_is_builtin", False):
            return
        frag = self.frag_list.fragments[frag_idx]
        begin, end = frag.seq_begin, frag.seq_end
        keys = self.frag_list.keys
        cmp = self.comparator.compare_timestamp
        lo = begin
        n = end - begin
        while n > 0:
            half = n // 2
            mid = lo + half
            if cmp(keys[mid], self.upper_bound) <= 0:
                n = half
            else:
                lo = mid + 1
                n = n - half - 1
        consumed = lo - begin
        seq_offset = self.seq_idx - begin
        if seq_offset < consumed:
            self.seq_idx = begin + consumed

    def _search_and_clamp(self, frag_idx):
        frag = self.frag_list.fragments[frag_idx]
        self.seq_idx = self._first_seq_le(frag.seq_begin, frag.seq_end)
        self._clamp(frag_idx)

    def _advance_forward(self):
        """Step to the next fragment, re-searching its seqnums and
        clamping. Returns False when the end position is reached."""
        self.frag += 1
        if self.frag >= len(self.frag_list.fragments):
            self._set_end(len(self.frag_list.seqnums))
            return False
        self._search_and_clamp(self.frag)
        return True

    def _step_back(self):
        """Step to the previous fragment, re-searching its seqnums
        and clamping. Returns False when the end position is reached
        (at the first fragment)."""
        if self.frag == 0:
            self._set_end(len(self.frag_list.seqnums))
            return False
        self.frag -= 1
        self._search_and_clamp(self.frag)
        return True

    # -- the positioning methods -----------------------------------------

    def valid(self):
        return (self.frag_list is not None
                and self.frag is not None)

    def seek_to_first(self):
        if len(self.frag_list.fragments) == 0:
            self._set_end(0)
            return
        self.frag = 0
        self.seq_idx = 0

    def seek_to_last(self):
        frags = self.frag_list.fragments
        if len(frags) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        self.frag = len(frags) - 1
        self.seq_idx = frags[-1].seq_end - 1

    def seek_to_covering_tombstone(self, key):
        frags = self.frag_list.fragments
        if len(frags) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        j = self._first_frag_end_gt(key)
        if j >= len(frags):
            self._set_end(len(self.frag_list.seqnums))
            return
        self.frag = j
        self._search_and_clamp(j)

    def seek_for_prev_to_covering_tombstone(self, key):
        frags = self.frag_list.fragments
        if len(frags) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        j = self._first_frag_start_gt(key)
        if j == 0:
            # No fragment starts at or before the key: the end
            # position with the seq_base variant.
            self._set_end(0)
            return
        self.frag = j - 1
        self._search_and_clamp(j - 1)

    def scan_forward_to_visible_tombstone(self):
        while True:
            if self.frag is None:
                return
            frag = self.frag_list.fragments[self.frag]
            if self.seq_idx == frag.seq_end:
                if not self._advance_forward():
                    return
                continue
            if self.frag_list.seqnums[self.seq_idx] >= self.arg6:
                return
            if not self._advance_forward():
                return

    def scan_backward_to_visible_tombstone(self):
        while True:
            if self.frag is None:
                return
            frag = self.frag_list.fragments[self.frag]
            if self.seq_idx == frag.seq_end:
                if not self._step_back():
                    return
                continue
            if self.frag_list.seqnums[self.seq_idx] >= self.arg6:
                return
            if not self._step_back():
                return

    def seek_to_top_first(self):
        if len(self.frag_list.fragments) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        self.frag = 0
        self._search_and_clamp(0)
        self.scan_forward_to_visible_tombstone()

    def seek_to_top_last(self):
        frags = self.frag_list.fragments
        if len(frags) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        self.frag = len(frags) - 1
        self._search_and_clamp(len(frags) - 1)
        self.scan_backward_to_visible_tombstone()

    def seek(self, key):
        if len(self.frag_list.fragments) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        self.seek_to_covering_tombstone(key)
        self.scan_forward_to_visible_tombstone()

    def seek_for_prev(self, key):
        if len(self.frag_list.fragments) == 0:
            self._set_end(len(self.frag_list.seqnums))
            return
        self.seek_for_prev_to_covering_tombstone(key)
        self.scan_backward_to_visible_tombstone()

    def top_next(self):
        if self.frag is None:
            return
        self.frag += 1
        if self.frag >= len(self.frag_list.fragments):
            # The seq pointer is left as-is; Valid() is false.
            self.frag = None
            return
        self._search_and_clamp(self.frag)
        self.scan_forward_to_visible_tombstone()

    def top_prev(self):
        if self.frag is None:
            return
        if self.frag == 0:
            # The end position with the seq_base variant (differs
            # from Prev's seq_end variant).
            self._set_end(0)
            return
        self.frag -= 1
        self._search_and_clamp(self.frag)
        self.scan_backward_to_visible_tombstone()

    def next(self):
        if self.frag is None:
            return
        frag = self.frag_list.fragments[self.frag]
        self.seq_idx += 1
        if self.seq_idx == frag.seq_end:
            self.frag += 1
            if self.frag >= len(self.frag_list.fragments):
                self.frag = None

    def prev(self):
        if self.seq_idx == 0:
            # The seq-array base: the end position (seq_end variant)
            # with the shadow updated too.
            self._set_end(len(self.frag_list.seqnums), update_shadow=True)
            return
        self.seq_idx -= 1
        if self.frag is None:
            self.frag = len(self.frag_list.fragments) - 1
        elif self.seq_idx == self.frag_list.fragments[self.frag].seq_begin - 1:
            self.frag -= 1

    # -- accessors --------------------------------------------------------

    def key(self):
        if self.frag is None:
            return self.cached_key
        if self.seq_idx == len(self.frag_list.seqnums):
            return self.cached_key
        if (self.frag, self.seq_idx) == (self.shadow_frag, self.shadow_seq_idx):
            return self.cached_key
        frag = self.frag_list.fragments[self.frag]
        seq = self.frag_list.seqnums[self.seq_idx]
        self.cached_key = frag.start + pack_sequence_and_type(seq, TYPE_RANGE_DELETION)
        self.shadow_frag = self.frag
        self.shadow_seq_idx = self.seq_idx
        return self.cached_key

    def value(self):
        if self.frag is None:
            return b""
        return self.frag_list.fragments[self.frag].end

    def slot11_user_key(self):
        """The shared slot-11 accessor: key() minus the 8-byte
        internal-key trailer."""
        k = self.key()
        return k[:-8] if len(k) >= 8 else b""

    def status(self):
        return "OK"

    def next_and_get_result(self):
        """NextAndGetResult: Next, then Valid, then key() into the
        result (key Slice at +0x0/+0x8, a u16 0 at +0x10)."""
        self.next()
        valid = self.valid()
        result = {"key": None, "extra_u16": 0, "valid": valid}
        if valid:
            result["key"] = self.key()
        return result

    def max_covering_tombstone_seqnum(self, key):
        self.seek_to_covering_tombstone(key)
        if not self.valid():
            return 0
        frag = self.frag_list.fragments[self.frag]
        if self.seq_idx == frag.seq_end:
            return 0
        if self.comparator.compare_without_timestamp(key, frag.start) < 0:
            return 0
        return self.frag_list.seqnums[self.seq_idx]

    # -- destructor ---------------------------------------------------------

    def key_cache_is_heap(self):
        """The cached-key string is heap-allocated once it outgrows
        the 15-byte inline buffer (libstdc++ SSO)."""
        return len(self.cached_key) > 15

    def destroy(self, delete_self=False):
        """D1 (delete_self=False) / D0 (delete_self=True). Returns the
        operation trace."""
        trace = ["reset_vtable"]
        if self.key_cache_is_heap():
            trace.append("free_key_cache_heap")
        if self.cache_ptr is not None:
            self.cache_ptr.release(trace)
        if self.second_ptr is not None:
            self.second_ptr.release(trace)
        trace.append("reset_base_vtable")
        trace.append("cleanable_do_cleanup")
        if delete_self:
            trace.append("operator_delete_this_0xc8")
        self.destroyed = True
        return trace
