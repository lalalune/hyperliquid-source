#!/usr/bin/env python3
"""Tests for the InternalIterator vtable tail model (node #115, RE-001).

Every test dispatches through `call_slot` -- the Python mirror of the
binary's indirect `call *off(%reg)` -- so the tests exercise the tail
behaviour end-to-end (inputs through the vtable to observable outputs),
not only the pinned constants. Ground truth is the packet
research/work-items/RE-001-iterator-vtable-tail-115/ (78 whole-function
excerpts, records.json, vtables.tsv).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from iterator_vtable_tail import (
    BlobCountingIterator,
    BlockBasedTableIterator,
    BlockIter,
    ClippingIterator,
    CompactionMergingIterator,
    ForwardIterator,
    ForwardLevelIterator,
    FragmentedRangeTombstoneIterator,
    HistoryTrimmingIterator,
    InternalIteratorBase,
    IterBoundCheck,
    IteratorWrapper,
    LevelIterator,
    MemTableIterator,
    MergingIterator,
    PinnedIteratorsManager,
    ReadaheadFileInfo,
    SequenceIterWrapper,
    Status,
    VectorIterator,
    call_slot,
)

INTERNAL_KEY = b"user-key\x00\x00\x00\x00\x00\x00\x00\x01"  # 8-byte trailer
USER_KEY = b"user-key"


class FakeIndexIter(InternalIteratorBase):
    """Index iterator whose value() is an IndexValue-like internal key."""

    def __init__(self, first_internal_key):
        super().__init__()
        self._first = first_internal_key

    def value(self):
        return self._first


def test_user_key_strips_trailer():
    base = InternalIteratorBase(key=INTERNAL_KEY)
    assert call_slot(base, 11) == USER_KEY
    # A 1-byte key plus the trailer still strips exactly 8 bytes.
    assert call_slot(InternalIteratorBase(key=b"k" + b"\x00" * 8), 11) == b"k"


def test_bbti_user_key_paths():
    block = BlockIter(key=INTERNAL_KEY)
    index = FakeIndexIter(INTERNAL_KEY)
    bbti = BlockBasedTableIterator(block, index_iter=index)
    # Not at first key from index: block_iter_.user_key().
    assert call_slot(bbti, 11) == USER_KEY
    # At first key from index: ExtractUserKey(index value's first key).
    bbti.is_at_first_key_from_index = True
    assert call_slot(bbti, 11) == USER_KEY
    # The index path uses the index key, not the block key.
    index2 = FakeIndexIter(b"other-key\x00\x00\x00\x00\x00\x00\x00\x02")
    bbti.index_iter = index2
    assert call_slot(bbti, 11) == b"other-key"


def test_prepare_value_defaults_and_caching():
    # Base default: always true.
    assert call_slot(InternalIteratorBase(), 14) is True
    # BBTI: true off the index path; materialize on the index path.
    bbti = BlockBasedTableIterator(BlockIter())
    assert call_slot(bbti, 14) is True
    bbti.is_at_first_key_from_index = True
    bbti.set_materialize(lambda: False)
    assert call_slot(bbti, 14) is False
    bbti.set_materialize(lambda: True)
    assert call_slot(bbti, 14) is True
    # MergingIterator caches: the child is asked once, then prepared.
    inner = InternalIteratorBase()
    calls = []
    orig = inner.prepare_value
    inner.prepare_value = lambda: calls.append(1) or orig()
    wrapper = IteratorWrapper(inner)
    merging = MergingIterator([], current=wrapper)
    assert call_slot(merging, 14) is True
    assert call_slot(merging, 14) is True
    assert len(calls) == 1
    # LevelIterator caches the same way via its +0xc9 flag.
    level = LevelIterator(file_iter=InternalIteratorBase())
    assert call_slot(level, 14) is True
    assert level.prepared is True
    # CompactionMergingIterator never prepares.
    assert call_slot(CompactionMergingIterator([]), 14) is False


def test_prepare_value_failure_captures_status():
    # ForwardIterator: a false child PrepareValue clears the flag and
    # copies the child status into the cache.
    child = InternalIteratorBase()
    child.prepare_value = lambda: False
    child.status = lambda: Status(2)
    fwd = ForwardIterator(child=child)
    assert call_slot(fwd, 14) is False
    assert fwd.prepared_flag is False
    assert fwd.status_cache.code == 2
    # MergingIterator: same failure path clears the wrapper flag.
    wrapper = IteratorWrapper(child)
    merging = MergingIterator([], current=wrapper)
    assert call_slot(merging, 14) is False
    assert wrapper.prepared_flag_cleared is True
    assert merging.status_cache.code == 2


def test_may_be_out_of_upper_bound():
    assert call_slot(InternalIteratorBase(), 15) is True
    # ClippingIterator: the clipped range is always in-bounds.
    assert call_slot(ClippingIterator(InternalIteratorBase()), 15) is False
    # LevelIterator: false while the +0x94 gate is clear, then delegates.
    inner = InternalIteratorBase()
    inner.may_be_out_of_upper_bound = lambda: False
    level = LevelIterator(file_iter=inner)
    assert call_slot(level, 15) is False
    level.may_be_gate = True
    assert call_slot(level, 15) is False
    inner.may_be_out_of_upper_bound = lambda: True
    assert call_slot(level, 15) is True
    # MergingIterator delegates to the current child.
    wrapper = IteratorWrapper(inner)
    assert call_slot(MergingIterator([], current=wrapper), 15) is True
    # CompactionMergingIterator: child flag 1 forces true.
    assert call_slot(
        CompactionMergingIterator([], current=inner, child_flag=1),
        15) is True


def test_upper_bound_check_result():
    assert call_slot(InternalIteratorBase(), 16) == IterBoundCheck.kUnknown
    # BBTI mapping: out-of-bound -> 1, beyond-cur-block -> 2, else 0.
    bbti = BlockBasedTableIterator(BlockIter())
    assert call_slot(bbti, 16) == IterBoundCheck.kUnknown
    bbti.block_upper_bound_check = 1
    assert call_slot(bbti, 16) == IterBoundCheck.kInbound
    bbti.is_out_of_bound = True
    assert call_slot(bbti, 16) == IterBoundCheck.kOutOfBound
    # ClippingIterator always reports kInbound.
    assert call_slot(ClippingIterator(InternalIteratorBase()), 16) \
        == IterBoundCheck.kInbound
    # MergingIterator returns the wrapper's cached byte.
    wrapper = IteratorWrapper(InternalIteratorBase())
    wrapper.bound_check_result = IterBoundCheck.kOutOfBound
    assert call_slot(MergingIterator([], current=wrapper), 16) \
        == IterBoundCheck.kOutOfBound
    # LevelIterator: unknown until a flag is set, then the cached byte.
    level = LevelIterator(file_iter=InternalIteratorBase())
    assert call_slot(level, 16) == IterBoundCheck.kUnknown
    level.cached_check = IterBoundCheck.kInbound
    level.flag_d0 = True
    assert call_slot(level, 16) == IterBoundCheck.kInbound


def test_pinned_iters_mgr_gating():
    # No manager -> not pinned, for every mgr-gated class.
    merging = MergingIterator([], current=IteratorWrapper(
        InternalIteratorBase()))
    assert call_slot(merging, 18) is False
    assert call_slot(merging, 19) is False
    level = LevelIterator(file_iter=InternalIteratorBase())
    assert call_slot(level, 18) is False
    fwd = ForwardIterator(child=InternalIteratorBase())
    assert call_slot(fwd, 18) is False
    # Manager present but pinning disabled -> still not pinned.
    mgr_off = PinnedIteratorsManager(pinning_enabled=False)
    merging.set_pinned_iters_mgr(mgr_off)
    assert call_slot(merging, 18) is False
    # Manager present and enabled -> delegates to the child.
    mgr = PinnedIteratorsManager(pinning_enabled=True)
    child = MemTableIterator()
    merging2 = MergingIterator([], current=IteratorWrapper(child))
    merging2.set_pinned_iters_mgr(mgr)
    assert call_slot(merging2, 18) is True  # MemTableIterator [18] is true
    assert call_slot(merging2, 19) is False  # [19] is the +0x5a flag (false)
    # SetPinnedItersMgr fans out to every child.
    seen = []
    kids = [InternalIteratorBase(), InternalIteratorBase()]
    for kid in kids:
        kid.set_pinned_iters_mgr = lambda m: seen.append(m)
    merging3 = MergingIterator(kids, current=IteratorWrapper(child))
    merging3.set_pinned_iters_mgr(mgr)
    assert seen == [mgr, mgr]


def test_bbti_pinning_paths():
    # BBTI IsKeyPinned: at first key from index -> index IsValuePinned.
    index = MemTableIterator(construction_flag=True)
    block = BlockIter(key_pinned=True, value_pinned=True)
    bbti = BlockBasedTableIterator(block, index_iter=index)
    mgr = PinnedIteratorsManager()
    bbti.set_pinned_iters_mgr(mgr)
    bbti.is_at_first_key_from_index = True
    assert call_slot(bbti, 18) is True  # index IsValuePinned (+0x5a = true)
    # Off the index path: block_iter_ IsKeyPinned, gated by the real-block
    # flag.
    bbti.is_at_first_key_from_index = False
    assert call_slot(bbti, 18) is False  # not yet a real block
    bbti.block_iter_points_to_real_block = True
    assert call_slot(bbti, 18) is True  # +0x109 ? +0x108 : 0
    # IsValuePinned is just the real-block flag (BlockIter's is always true).
    assert call_slot(bbti, 19) is True
    bbti.block_iter_points_to_real_block = False
    assert call_slot(bbti, 19) is False


def test_block_iter_pinning_bytes():
    # [18] = +0x109 ? +0x108 : 0 ; [19] = +0x109.
    assert call_slot(BlockIter(value_pinned=True, key_pinned=True), 18) is True
    assert call_slot(BlockIter(value_pinned=True, key_pinned=False), 18) is False
    assert call_slot(BlockIter(value_pinned=False, key_pinned=True), 18) is False
    assert call_slot(BlockIter(value_pinned=True), 19) is True
    assert call_slot(BlockIter(value_pinned=False), 19) is False


def test_constant_pinning_classes():
    assert call_slot(MemTableIterator(), 18) is True
    assert call_slot(MemTableIterator(construction_flag=True), 19) is True
    assert call_slot(MemTableIterator(construction_flag=False), 19) is False
    assert call_slot(FragmentedRangeTombstoneIterator(), 18) is False
    assert call_slot(FragmentedRangeTombstoneIterator(), 19) is True
    assert call_slot(VectorIterator(), 18) is True
    assert call_slot(VectorIterator(), 19) is True
    assert call_slot(CompactionMergingIterator([]), 18) is False
    assert call_slot(CompactionMergingIterator([]), 19) is False


def test_get_property():
    # Base default: NotSupported (code 3).
    assert call_slot(InternalIteratorBase(), 20, "anything", []).code == 3
    # ForwardIterator: the super-version-number property answers OK.
    fwd = ForwardIterator(super_version_number=42)
    out = []
    st = call_slot(fwd, 20, ForwardIterator.PROPERTY, out)
    assert st.ok() and out == ["42"]
    # Any other property: InvalidArgument (code 4).
    assert call_slot(fwd, 20, "rocksdb.iterator.is-key-pinned", []).code == 4
    assert call_slot(fwd, 20, "", []).code == 4
    # BlobCountingIterator forwards the property to its inner iterator.
    inner = ForwardIterator(super_version_number=7)
    blob = BlobCountingIterator(inner)
    out = []
    assert call_slot(blob, 20, ForwardIterator.PROPERTY, out).ok()
    assert out == ["7"]


def test_readahead_state_round_trip():
    bbti = BlockBasedTableIterator(
        BlockIter(), index_iter=InternalIteratorBase(),
        table={"readahead": True})
    bbti.readahead_holder = ReadaheadFileInfo(b"readahead-bytes")
    info = ReadaheadFileInfo()
    call_slot(bbti, 21, info)
    assert info.data == b"readahead-bytes"
    # SetReadaheadState stores the 16-byte slice, then forwards.
    new_info = ReadaheadFileInfo(b"new-state")
    call_slot(bbti, 22, new_info)
    assert bbti.readahead_state.data == b"new-state"
    # Base defaults are no-ops and leave the info untouched.
    info2 = ReadaheadFileInfo(b"keep")
    call_slot(InternalIteratorBase(), 21, info2)
    call_slot(InternalIteratorBase(), 22, info2)
    assert info2.data == b"keep"


def test_delete_range_sentinel_key():
    assert call_slot(InternalIteratorBase(), 23) is False
    # LevelIterator returns its +0xf8 flag.
    level = LevelIterator()
    assert call_slot(level, 23) is False
    level.is_delete_range_sentinel = True
    assert call_slot(level, 23) is True
    # Wrappers delegate to the wrapped iterator.
    inner = LevelIterator()
    inner.is_delete_range_sentinel = True
    assert call_slot(SequenceIterWrapper(inner), 23) is True
    assert call_slot(HistoryTrimmingIterator(inner), 23) is True
    assert call_slot(BlobCountingIterator(inner), 23) is True
    assert call_slot(ClippingIterator(inner), 23) is True
    # CompactionMergingIterator: the child +0x50 flag decides.
    assert call_slot(
        CompactionMergingIterator([], child_flag=1), 23) is True
    assert call_slot(
        CompactionMergingIterator([], child_flag=0), 23) is False


def test_dispatch_routes_by_slot_index():
    # The same object answers differently per slot: the vtable, not the
    # method name, decides.
    bbti = BlockBasedTableIterator(BlockIter())
    assert call_slot(bbti, 14) is True
    assert call_slot(bbti, 15) is True
    assert call_slot(bbti, 16) == IterBoundCheck.kUnknown
    assert call_slot(bbti, 18) is False
    assert call_slot(bbti, 23) is False
    # Unknown slot indexes are a dispatch error, not a silent default.
    try:
        call_slot(bbti, 99)
    except KeyError:
        pass
    else:
        raise AssertionError("slot 99 should not dispatch")
