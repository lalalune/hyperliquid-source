#!/usr/bin/env python3
"""Python model of the InternalIterator vtable tail dispatch (node #115).

RE-001 work item: pin the C++ names and behaviours of the
InternalIteratorBase vtable tail slots [11] and [14]-[23] in node #115
(RocksDB v8.1.1, binary work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Every class carries an explicit VTABLE mapping slot index -> method,
mirroring the binary vtables (research/work-items/
RE-001-iterator-vtable-tail-115/vtables.tsv). `call_slot` dispatches
through that table exactly as the binary's indirect `call *off(%reg)`
does. The defaults are the base-class stubs; each override reproduces
the whole-function behaviour read from the binary excerpts.

Slot map:
    [11] user_key() -> Slice (internal key minus the 8-byte trailer)
    [14] PrepareValue() -> bool
    [15] MayBeOutOfUpperBound() -> bool
    [16] UpperBoundCheckResult() -> IterBoundCheck
    [17] SetPinnedItersMgr(PinnedIteratorsManager*) -> None
    [18] IsKeyPinned() -> bool
    [19] IsValuePinned() -> bool
    [20] GetProperty(name, out) -> Status
    [21] GetReadaheadState(ReadaheadFileInfo*) -> None
    [22] SetReadaheadState(ReadaheadFileInfo*) -> None
    [23] IsDeleteRangeSentinelKey() -> bool
"""
from enum import IntEnum

# Status codes (rocksdb::Status::Code).
STATUS_OK = 0
STATUS_NOT_SUPPORTED = 3
STATUS_INVALID_ARGUMENT = 4


class IterBoundCheck(IntEnum):
    kUnknown = 0
    kOutOfBound = 1
    kInbound = 2


class Status:
    """rocksdb::Status: 16 bytes {code, subcode, state_}."""

    def __init__(self, code=STATUS_OK, subcode=0, state=None):
        self.code = code
        self.subcode = subcode
        self.state = state

    def ok(self):
        return self.code == STATUS_OK

    def __eq__(self, other):
        return (isinstance(other, Status) and self.code == other.code
                and self.subcode == other.subcode
                and self.state == other.state)

    def __repr__(self):
        return f"Status(code={self.code}, subcode={self.subcode})"


def not_supported():
    return Status(STATUS_NOT_SUPPORTED)


class PinnedIteratorsManager:
    """PinnedIteratorsManager; the +0x20 byte is the pinning-enabled flag."""

    def __init__(self, pinning_enabled=True):
        self.pinning_enabled = pinning_enabled


class ReadaheadFileInfo:
    """The 16-byte readahead state (a Slice: data + length)."""

    def __init__(self, data=b""):
        self.data = data

    def __eq__(self, other):
        return isinstance(other, ReadaheadFileInfo) and self.data == other.data


class IteratorWrapper:
    """IteratorWrapperBase: caches valid/key results for a child iterator.

    +0x18 bound_check_result, +0x19 prepared flag, +0x20 cleared when
    PrepareValue fails.
    """

    def __init__(self, inner):
        self.inner = inner
        self.bound_check_result = IterBoundCheck.kUnknown
        self.prepared = False
        self.prepared_flag_cleared = False


class InternalIteratorBase:
    """rocksdb::InternalIteratorBase<Slice> -- the base-class defaults."""

    VTABLE = {
        11: "user_key",
        14: "prepare_value",
        15: "may_be_out_of_upper_bound",
        16: "upper_bound_check_result",
        17: "set_pinned_iters_mgr",
        18: "is_key_pinned",
        19: "is_value_pinned",
        20: "get_property",
        21: "get_readahead_state",
        22: "set_readahead_state",
        23: "is_delete_range_sentinel_key",
    }

    def __init__(self, key=b"", value=b""):
        self._key = key
        self._value = value

    def key(self):
        return self._key

    def value(self):
        return self._value

    def status(self):
        return Status()

    # --- tail slots (base defaults, 0x5df7650 etc.) ---
    def user_key(self):
        return self.key()[:-8]

    def prepare_value(self):
        return True

    def may_be_out_of_upper_bound(self):
        return True

    def upper_bound_check_result(self):
        return IterBoundCheck.kUnknown

    def set_pinned_iters_mgr(self, mgr):
        return None

    def is_key_pinned(self):
        return False

    def is_value_pinned(self):
        return False

    def get_property(self, name, out):
        return not_supported()

    def get_readahead_state(self, info):
        return None

    def set_readahead_state(self, info):
        return None

    def is_delete_range_sentinel_key(self):
        return False


def call_slot(it, slot, *args):
    """Dispatch through the iterator's vtable at the given slot index."""
    name = it.VTABLE[slot]
    return getattr(it, name)(*args)


class _Delegate(InternalIteratorBase):
    """A wrapper whose tail slots all delegate to an inner iterator."""

    INNER_OFFSET = 0x28

    def __init__(self, inner):
        super().__init__()
        self.inner = inner

    def user_key(self):
        return call_slot(self.inner, 11)

    def prepare_value(self):
        return call_slot(self.inner, 14)

    def may_be_out_of_upper_bound(self):
        return call_slot(self.inner, 15)

    def upper_bound_check_result(self):
        return call_slot(self.inner, 16)

    def set_pinned_iters_mgr(self, mgr):
        return call_slot(self.inner, 17, mgr)

    def is_key_pinned(self):
        return call_slot(self.inner, 18)

    def is_value_pinned(self):
        return call_slot(self.inner, 19)

    def get_property(self, name, out):
        return call_slot(self.inner, 20, name, out)

    def is_delete_range_sentinel_key(self):
        return call_slot(self.inner, 23)


class BlobCountingIterator(_Delegate):
    """rocksdb::BlobCountingIterator: pure delegation to inner (+0x28)."""


class HistoryTrimmingIterator(InternalIteratorBase):
    """rocksdb::HistoryTrimmingIterator: delegates [18], [19], [23] only.

    All other tail slots are the base defaults (shared stubs).
    """

    def __init__(self, inner):
        super().__init__()
        self.inner = inner  # +0x28

    def is_key_pinned(self):
        return call_slot(self.inner, 18)

    def is_value_pinned(self):
        return call_slot(self.inner, 19)

    def is_delete_range_sentinel_key(self):
        return call_slot(self.inner, 23)


class ClippingIterator(_Delegate):
    """rocksdb::ClippingIterator: clips the inner iterator to a range."""

    def __init__(self, inner):
        super().__init__(inner)
        self.prepared_flag = True  # +0x48

    def prepare_value(self):
        ok = call_slot(self.inner, 14)
        if not ok:
            self.prepared_flag = False
        return ok

    def may_be_out_of_upper_bound(self):
        return False  # the clipped range is always in-bounds

    def upper_bound_check_result(self):
        return IterBoundCheck.kInbound

    def get_property(self, name, out):
        # Copies prop_name, then forwards to the inner GetProperty.
        return call_slot(self.inner, 20, str(name), out)


class SequenceIterWrapper(InternalIteratorBase):
    """rocksdb::SequenceIterWrapper: delegates [23] to wrapped (+0x38)."""

    def __init__(self, wrapped):
        super().__init__()
        self.wrapped = wrapped  # +0x38

    def is_delete_range_sentinel_key(self):
        return call_slot(self.wrapped, 23)


class BlockIter(InternalIteratorBase):
    """rocksdb::BlockIter<Slice>: pinning bytes +0x108/+0x109."""

    def __init__(self, key=b"", value=b"", key_pinned=False,
                 value_pinned=False):
        super().__init__(key, value)
        self.key_pinned = key_pinned    # +0x108
        self.value_pinned = value_pinned  # +0x109

    def is_key_pinned(self):
        return self.value_pinned and self.key_pinned

    def is_value_pinned(self):
        return self.value_pinned


class DataBlockIter(BlockIter):
    """rocksdb::DataBlockIter: BlockIter's [18]/[19], rest defaults."""


class MetaBlockIter(BlockIter):
    """rocksdb::MetaBlockIter: BlockIter's [18]/[19], rest defaults."""


class MemTableIterator(InternalIteratorBase):
    """rocksdb::MemTableIterator: keys arena-pinned."""

    def __init__(self, key=b"", value=b"", construction_flag=False):
        super().__init__(key, value)
        self.construction_flag = construction_flag  # +0x5a

    def is_key_pinned(self):
        return True

    def is_value_pinned(self):
        return self.construction_flag


class FragmentedRangeTombstoneIterator(InternalIteratorBase):
    """rocksdb::FragmentedRangeTombstoneIterator (see #3900)."""

    def is_key_pinned(self):
        return False  # key() rebuilds into a cached std::string

    def is_value_pinned(self):
        return True  # value() is the stable fragment end key


class VectorIterator(InternalIteratorBase):
    """rocksdb::VectorIterator: owns its entries, both pinned."""

    def is_key_pinned(self):
        return True

    def is_value_pinned(self):
        return True


class EmptyInternalIterator(InternalIteratorBase):
    """rocksdb::EmptyInternalIterator: all base defaults."""


class TruncatedRangeDelMergingIter(InternalIteratorBase):
    """rocksdb::TruncatedRangeDelMergingIter: all base defaults."""


class PlainTableIterator(InternalIteratorBase):
    """rocksdb::PlainTableIterator: all base defaults."""


class CuckooTableIterator(InternalIteratorBase):
    """rocksdb::CuckooTableIterator: all base defaults."""


class BlockBasedTableIterator(InternalIteratorBase):
    """rocksdb::BlockBasedTableIterator (v8.1.1 header + binary)."""

    def __init__(self, block_iter, index_iter=None, table=None):
        super().__init__()
        self.block_iter = block_iter          # +0x58 subobject
        self.index_iter = index_iter          # +0x28
        self.table = table                    # +0x38
        self.pinned_mgr = None                # +0x50
        self.is_at_first_key_from_index = False  # +0x290
        self.is_out_of_bound = False          # +0x28a
        self.block_upper_bound_check = 2      # +0x28c (kUnknown)
        self.block_iter_points_to_real_block = False  # +0x289
        self.readahead_state = ReadaheadFileInfo()   # +0x260
        self.readahead_holder = None          # +0x280
        self._materialize = lambda: True

    def set_materialize(self, fn):
        self._materialize = fn

    def user_key(self):
        if self.is_at_first_key_from_index:
            first = self.index_iter.value()
            # ExtractUserKey(index_iter_->value().first_internal_key):
            # first_internal_key is the value's (ptr, len) with the
            # 8-byte trailer stripped.
            return first[:-8]
        return self.block_iter.key()[:-8]

    def prepare_value(self):
        if self.is_at_first_key_from_index:
            return self._materialize()
        return True

    def upper_bound_check_result(self):
        if self.is_out_of_bound:
            return IterBoundCheck.kOutOfBound
        if self.block_upper_bound_check == 1:
            return IterBoundCheck.kInbound
        return IterBoundCheck.kUnknown

    def set_pinned_iters_mgr(self, mgr):
        self.pinned_mgr = mgr

    def _mgr_active(self):
        return (self.pinned_mgr is not None
                and self.pinned_mgr.pinning_enabled)

    def is_key_pinned(self):
        if not self._mgr_active():
            return False
        if self.is_at_first_key_from_index:
            return call_slot(self.index_iter, 19)
        if not self.block_iter_points_to_real_block:
            return False
        return self.block_iter.is_key_pinned()

    def is_value_pinned(self):
        if not self._mgr_active():
            return False
        return self.block_iter_points_to_real_block

    def get_readahead_state(self, info):
        if self.readahead_holder is not None:
            info.data = self.readahead_holder.data
        if self.index_iter is not None:
            call_slot(self.index_iter, 21, info)

    def set_readahead_state(self, info):
        if self.table is not None and self.table.get("readahead", False):
            self.readahead_state = ReadaheadFileInfo(info.data)
        if self.index_iter is not None:
            call_slot(self.index_iter, 22, info)


class MergingIterator(InternalIteratorBase):
    """rocksdb::MergingIterator: merges sorted child iterators."""

    def __init__(self, children, current=None):
        super().__init__()
        self.children = children              # +0x38..+0x40
        self.current = current                # +0xb0 (IteratorWrapper*)
        self.pinned_mgr = None                # +0x148
        self.status_cache = Status()          # +0xb8/+0xba/+0xc0

    def prepare_value(self):
        wrapper = self.current
        if wrapper.prepared:
            return True
        ok = call_slot(wrapper.inner, 14)
        if not ok:
            wrapper.prepared_flag_cleared = True
            self.status_cache = wrapper.inner.status()
            return False
        wrapper.prepared = True
        return True

    def may_be_out_of_upper_bound(self):
        return call_slot(self.current.inner, 15)

    def upper_bound_check_result(self):
        return self.current.bound_check_result

    def set_pinned_iters_mgr(self, mgr):
        self.pinned_mgr = mgr
        for child in self.children:
            call_slot(child, 17, mgr)

    def _mgr_active(self):
        return (self.pinned_mgr is not None
                and self.pinned_mgr.pinning_enabled)

    def is_key_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.current.inner, 18)

    def is_value_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.current.inner, 19)


class LevelIterator(InternalIteratorBase):
    """rocksdb::LevelIterator (anonymous namespace)."""

    def __init__(self, file_iter=None):
        super().__init__()
        self.file_iter = file_iter            # +0xb0
        self.may_be_gate = False              # +0x94
        self.cached_check = IterBoundCheck.kUnknown  # +0xc8
        self.prepared = False                 # +0xc9
        self.flag_d0 = False                  # +0xd0
        self.pinned_mgr = None                # +0xd8
        self.is_delete_range_sentinel = False  # +0xf8

    def prepare_value(self):
        if self.prepared:
            return True
        ok = call_slot(self.file_iter, 14)
        if not ok:
            self.flag_d0 = False
            return False
        self.prepared = True
        return True

    def may_be_out_of_upper_bound(self):
        if not self.may_be_gate:
            return False
        return call_slot(self.file_iter, 15)

    def upper_bound_check_result(self):
        if not self.flag_d0 and not self.is_delete_range_sentinel:
            return IterBoundCheck.kUnknown
        return self.cached_check

    def set_pinned_iters_mgr(self, mgr):
        self.pinned_mgr = mgr
        if self.file_iter is not None:
            call_slot(self.file_iter, 17, mgr)

    def _mgr_active(self):
        return (self.pinned_mgr is not None
                and self.pinned_mgr.pinning_enabled)

    def is_key_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.file_iter, 18)

    def is_value_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.file_iter, 19)

    def is_delete_range_sentinel_key(self):
        return self.is_delete_range_sentinel


class ForwardIterator(InternalIteratorBase):
    """rocksdb::ForwardIterator: forward-only, seek-based."""

    PROPERTY = "rocksdb.iterator.super-version-number"

    def __init__(self, child=None, super_version_number=0):
        super().__init__()
        self.child = child                    # +0x158
        self.pinned_mgr = None                # +0x1e0
        self.prepared_flag = True             # +0x160
        self.status_cache = Status()          # +0x178/+0x17c/+0x180
        self.super_version_number = super_version_number  # +0x100/+0x218
        self.immutable_iter = None            # +0x108
        self.child_lists = ([], [])           # +0x110..+0x118, +0x128..+0x130

    def prepare_value(self):
        ok = call_slot(self.child, 14)
        if not ok:
            self.prepared_flag = False
            self.status_cache = self.child.status()
        return ok

    def set_pinned_iters_mgr(self, mgr):
        self.pinned_mgr = mgr
        self.update_children_pinned_iters_mgr()

    def update_children_pinned_iters_mgr(self):
        if self.immutable_iter is not None:
            call_slot(self.immutable_iter, 17, self.pinned_mgr)
        for lst in self.child_lists:
            for child in lst:
                call_slot(child, 17, self.pinned_mgr)

    def _mgr_active(self):
        return (self.pinned_mgr is not None
                and self.pinned_mgr.pinning_enabled)

    def is_key_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.child, 18)

    def is_value_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.child, 19)

    def get_property(self, name, out):
        if name != self.PROPERTY:
            return Status(STATUS_INVALID_ARGUMENT)
        out.append(str(self.super_version_number))
        return Status()


class ForwardLevelIterator(InternalIteratorBase):
    """rocksdb::ForwardLevelIterator: two-level wrapper."""

    def __init__(self, inner=None):
        super().__init__()
        self.inner = inner                    # +0x58
        self.pinned_mgr = None                # +0x60
        self.prepared_flag = True             # +0x40

    def prepare_value(self):
        ok = call_slot(self.inner, 14)
        if not ok:
            self.prepared_flag = False
        return ok

    def set_pinned_iters_mgr(self, mgr):
        self.pinned_mgr = mgr
        if self.inner is not None:
            call_slot(self.inner, 17, mgr)

    def _mgr_active(self):
        return (self.pinned_mgr is not None
                and self.pinned_mgr.pinning_enabled)

    def is_key_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.inner, 18)

    def is_value_pinned(self):
        if not self._mgr_active():
            return False
        return call_slot(self.inner, 19)


class CompactionMergingIterator(InternalIteratorBase):
    """rocksdb::CompactionMergingIterator: compaction-time merging."""

    def __init__(self, children, current=None, child_flag=0):
        super().__init__()
        self.children = children
        self.current = current                # +0xa0
        self.child_flag = child_flag          # current +0x50
        self.pinned_mgr = None                # +0x130

    def prepare_value(self):
        return False

    def may_be_out_of_upper_bound(self):
        if self.child_flag == 1:
            return True
        return call_slot(self.current, 15)

    def upper_bound_check_result(self):
        if self.child_flag == 1:
            return IterBoundCheck.kUnknown
        return self.current.bound_check_result

    def set_pinned_iters_mgr(self, mgr):
        self.pinned_mgr = mgr
        for child in self.children:
            call_slot(child, 17, mgr)

    def is_key_pinned(self):
        return False

    def is_value_pinned(self):
        return False

    def is_delete_range_sentinel_key(self):
        return self.child_flag == 1
