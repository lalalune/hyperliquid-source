"""Model of the TableCache range-tombstone consultation pinned by
RE-001-tablecache-tombstone-consumers-115 (node #115).

Two consumers consult the fragmented range tombstones through the
same shared update:

* ``TableCache::UpdateRangeTombstoneSeqnums`` (0x5f3d4f0): loops over
  a level range and, for every level whose bit is CLEAR in the
  combined mask, asks the fragmented iterator for the max covering
  tombstone seqnum and raises the cached max.
* ``TableCache::Get`` (0x5f40070): before the table lookup, gates on
  the cached max slot, the +0x35 skip flag and the slot-0x18
  canonical, then performs the same raise-and-refresh once.

The callee ``MaxCoveringTombstoneSeqnum`` (0x5f32900) is #3900's
ground and is modelled here by contract: seek the covering
tombstone, return 0 when invalid / at the range end / when the
fragment start key is greater than the key, else the seqnum at the
positioned pointer. The key-array entry identity (fragment start
key vs end key vs timestamp key) is open in #3900 and stays open
here: the model carries the Slice, it does not name it.
"""

NULL_STUB = "null_stub_0x5eba930"

# The slot-0x18 canonical (the null-returning stub). A table reader
# whose slot 0x18 is this stub has no range tombstones to consult:
# CuckooTableReader (vtable 0x64d5e90) and PlainTableReader (vtable
# 0x64d6750) both install it. BlockBasedTable overrides the slot.


class Fragment:
    """One range-tombstone fragment: [start_key, end_key) with seqnums
    sorted DESCENDING and one 16-byte Slice entry per seqnum in the
    parallel key array."""

    def __init__(self, start_key, end_key, seqnums, key_entries):
        self.start_key = start_key
        self.end_key = end_key
        self.seqnums = list(seqnums)  # descending
        self.key_entries = list(key_entries)  # one Slice per seqnum

    def __repr__(self):
        return "Fragment(%r, %r, %r)" % (
            self.start_key, self.end_key, self.seqnums)


class FragmentedTombstoneIterator:
    """Minimal iterator over a fragment list, modelling the
    MaxCoveringTombstoneSeqnum contract from #3900. The read seq
    (+0x70) is fixed at construction; each call re-seeks."""

    def __init__(self, fragments, read_seq):
        self.fragments = list(fragments)
        self.read_seq = read_seq
        self.seq_index = None  # index into the covering fragment's seqnums
        self.fragment = None

    def max_covering_seqnum(self, user_key):
        """Return (max_seqnum, seq_index, fragment) for user_key.

        0 when no fragment covers the key, when every seqnum in the
        covering fragment is above the read seq, or when the fragment
        start key is greater than the key.
        """
        self.fragment = None
        self.seq_index = None
        for frag in self.fragments:
            if frag.start_key <= user_key < frag.end_key:
                self.fragment = frag
                break
        if self.fragment is None:
            return (0, None, None)
        if self.fragment.start_key > user_key:
            return (0, None, None)
        for i, seq in enumerate(self.fragment.seqnums):
            if seq <= self.read_seq:
                self.seq_index = i
                return (seq, i, self.fragment)
        return (0, None, self.fragment)

    def covering_key_entry(self):
        """The key-array Slice at the positioned seqnum's index:
        (seq_ptr - seq_base) >> 3 gives the index, the 16-byte Slice
        at key_base + index * 16 is the entry. Returns None when the
        iterator is not positioned."""
        if self.fragment is None or self.seq_index is None:
            return None
        return self.fragment.key_entries[self.seq_index]


class CachedTombstoneState:
    """The per-record cached tombstone state both consumers update:
    a pointer cell holding the cached max covering seqnum (+0x1b0),
    the cached covering-key string (+0x190, None when the slot is
    null) and the has-covering-key flag byte (+0x198)."""

    def __init__(self, max_seqnum=0, covering_key=None):
        self.max_seqnum = max_seqnum
        self.covering_key = covering_key  # None models a null string slot
        self.has_covering_key = False

    def raise_max(self, new_max, covering_entry):
        """Raise the cached max iff new_max is strictly greater; on a
        raise, refresh the covering-key string when the slot is
        non-null and set the flag byte. Returns True on a raise."""
        if new_max <= self.max_seqnum:
            return False
        self.max_seqnum = new_max
        if self.covering_key is not None and covering_entry is not None:
            self.covering_key = covering_entry
        self.has_covering_key = True
        return True


def build_iterator(slot_0x18, receiver, options):
    """The slot-0x18 iterator build both consumers use. When the
    slot is the null canonical, no iterator exists (the stub returns
    null); otherwise the slot's implementation builds one."""
    if slot_0x18 == NULL_STUB:
        return None
    return slot_0x18(receiver, options)


def update_range_tombstone_seqnums(levels, skip_mask, slot_0x18,
                                   receiver, options):
    """TableCache::UpdateRangeTombstoneSeqnums (0x5f3d4f0).

    levels: list of (level_index, CachedTombstoneState, level_key)
    in [start, end) order. skip_mask: integer whose set bits mark
    levels to SKIP (mask1 | mask2 | base+0xf08 in the binary). The
    iterator is built once via slot 0x18, re-seeks once per level
    with that level's key Slice, and is released via slot 0x8 at
    the end. Returns (levels_updated, iterator_built).
    """
    if slot_0x18 == NULL_STUB:
        return (0, False)
    iterator = slot_0x18(receiver, options)
    if iterator is None:
        return (0, False)
    updated = 0
    for level_index, state, level_key in levels:
        if (skip_mask >> level_index) & 1:
            continue
        max_seq, _, _ = iterator.max_covering_seqnum(level_key)
        if state.raise_max(max_seq, iterator.covering_key_entry()):
            updated += 1
    # Slot 0x8 (deleting dtor) releases the iterator.
    return (updated, True)


def table_cache_get_tombstone_gate(state, user_key, skip_tombstones,
                                   slot_0x18, receiver, options):
    """The TableCache::Get tombstone consultation (0x5f40070,
    0x5f40176..0x5f405c2).

    Gate order, exactly as the binary applies it:
      1. cached max slot null (state is None) -> proceed, no consult
      2. +0x35 skip flag set -> proceed, no consult
      3. slot 0x18 is the null canonical -> proceed, no consult
      4. iterator build returns null -> proceed, no consult
      5. else consult, raise-and-refresh, release via slot 0x8,
         then proceed to the table Get.
    Returns (consulted, raised) where consulted says whether the
    iterator was built and MaxCoveringTombstoneSeqnum ran.
    """
    if state is None:
        return (False, False)
    if skip_tombstones:
        return (False, False)
    if slot_0x18 == NULL_STUB:
        return (False, False)
    iterator = slot_0x18(receiver, options)
    if iterator is None:
        return (False, False)
    max_seq, _, _ = iterator.max_covering_seqnum(user_key)
    raised = state.raise_max(max_seq, iterator.covering_key_entry())
    return (True, raised)


def covering_key_index(seq_ptr_offset, seq_base_offset):
    """The fragment-index arithmetic both consumers use to find the
    key-array entry for the returned seqnum:
    (seq_ptr - seq_base) >> 3 gives the seqnum index; the entry is
    the 16-byte Slice at key_base + index * 16."""
    return (seq_ptr_offset - seq_base_offset) >> 3
