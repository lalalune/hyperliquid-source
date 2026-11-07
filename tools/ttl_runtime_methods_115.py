"""Python model of node #115's TTL runtime methods.

Pinned from the real binary work/hl-node-115.bin (node #115,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
in research/work-items/RE-001-ttl-runtime-methods-115/:

* TtlMergeOperator 0x6206610 FullMergeV2 and 0x6201c90 PartialMergeMulti:
  a TTL value is payload + a 4-byte little-endian timestamp suffix.
  Both methods strip the last 4 bytes from the existing value and
  every operand, delegate to the wrapped operator, and on success
  append the current time (low 32 bits) to the merged value.
* TtlCompactionFilter 0x6203520 Filter and 0x6203400 expiry helper:
  expired values are removed; otherwise the wrapped filter decides
  on the timestamp-stripped value, and a changed value gets its
  original timestamp re-appended.
* TtlCompactionFilterFactory 0x6202ba0 CreateCompactionFilter:
  wraps the factory's own filter in a TtlCompactionFilter.
* The Configurable slots: PrepareOptions resolves a null clock via
  0x5fcf430, ValidateOptions errors on null wrapped/clock fields,
  IsInstanceOf matches the legacy names "Merge By TTL" (merge
  operator) and "Delete By TTL" (compaction filter) as well as Name().
* FilterV2 0x5d2e4a0 / FilterV3 0x5d2f8a0 decision mapping.

The error strings carry their db_ttl_impl.cc source lines, e.g.
"[%s:36] Error: Could not remove timestamp from existing value."
"""

import struct

TS_LEN = 4
SOURCE_FILE = "utilities/ttl/db_ttl_impl.cc"

# Filter Decision values (compaction_filter.h).
KEEP = 0
REMOVE = 1
CHANGE_VALUE = 2

# CompactionFilter ValueType values.
K_VALUE = 0
K_MERGE_OPERAND = 1
K_BLOB_INDEX = 2
K_WIDE_COLUMN_ENTITY = 3

# Max std::string size guard seen at the _M_append sites.
MAX_STRING_LEN = 0x3FFFFFFFFFFFFFFF


class ClockFailure(Exception):
    """The clock's GetCurrentTime returned a non-ok Status."""


class LengthError(Exception):
    """std::string::append length guard tripped."""


class Clock:
    """A SystemClock whose GetCurrentTime can be made to fail."""

    def __init__(self, now_seconds, fail=False):
        self.now_seconds = now_seconds
        self.fail = fail

    def get_current_time(self):
        if self.fail:
            raise ClockFailure("GetCurrentTime failed")
        return self.now_seconds


class Logger:
    """Records the merge-error log calls (helper 0x5fceda0).

    Each entry is (code, message, source_file): the binary calls the
    helper with code 3, the logger, the formatted message and the
    source file literal utilities/ttl/db_ttl_impl.cc.
    """

    def __init__(self):
        self.entries = []

    def log_error(self, message):
        self.entries.append((3, message, SOURCE_FILE))


def _err(line, text):
    return "[%s:%d] Error: %s" % (SOURCE_FILE, line, text)


def strip_timestamp(value):
    """Return the payload of a TTL value (everything but the last 4 bytes)."""
    return value[:-TS_LEN]


def read_timestamp(value):
    """Read the 4-byte little-endian timestamp suffix of a TTL value."""
    return struct.unpack("<I", value[-TS_LEN:])[0]


def append_timestamp(value, now_seconds):
    """Append the low 32 bits of the current time to a payload."""
    if len(value) + TS_LEN > MAX_STRING_LEN:
        raise LengthError("basic_string::append")
    return value + struct.pack("<I", now_seconds & 0xFFFFFFFF)


def is_expired(value, ttl, clock):
    """The expiry helper 0x6203400: (uint32)(last 4 bytes) + ttl < now.

    A non-positive ttl never expires.  The 4-byte load zero-extends
    and the add is 64-bit (mov -0x4(%rdx,%rax,1),%eax; add %rbx,%rax),
    so the sum does NOT wrap at 32 bits.
    """
    if ttl <= 0:
        return False
    return (read_timestamp(value) + ttl) < clock.get_current_time()


class MergeResult:
    def __init__(self, ok, new_value, error=None):
        self.ok = ok
        self.new_value = new_value
        self.error = error


class WrappedMergeOperator:
    """Interface for the wrapped MergeOperator (vtable slots 19-24)."""

    def full_merge_v2(self, key, existing_value, operands):
        """Return (ok, merged_value)."""
        raise NotImplementedError

    def partial_merge_multi(self, key, operands):
        """Return (ok, merged_value)."""
        raise NotImplementedError


class PutMergeOperator(WrappedMergeOperator):
    """PutOperator-style wrapped operator: last operand wins.

    (PutOperator::FullMerge 0x61f4d60 assigns the last operand of the
    deque to *new_value; used here as the concrete wrapped operator
    for end-to-end checks.)
    """

    def full_merge_v2(self, key, existing_value, operands):
        if operands:
            return True, operands[-1]
        return True, existing_value if existing_value is not None else b""

    def partial_merge_multi(self, key, operands):
        if operands:
            return True, operands[-1]
        return True, b""


class RecordingMergeOperator(WrappedMergeOperator):
    """Wrapped operator that records what it was called with."""

    def __init__(self, reply=True, reply_value=b"merged"):
        self.calls = []
        self.reply = reply
        self.reply_value = reply_value

    def full_merge_v2(self, key, existing_value, operands):
        self.calls.append(("full_merge_v2", key, existing_value,
                           list(operands)))
        return self.reply, self.reply_value

    def partial_merge_multi(self, key, operands):
        self.calls.append(("partial_merge_multi", key, list(operands)))
        return self.reply, self.reply_value


class TtlMergeOperator:
    """TtlMergeOperator (vtable 0x64d9558, object size 0x38).

    Fields: +0x20 shared_ptr<MergeOperator> (wrapped), +0x30 SystemClock*.
    """

    NAME = "TtlMergeOperator"
    LEGACY_NAME = "Merge By TTL"

    def __init__(self, wrapped, clock):
        self.wrapped = wrapped
        self.clock = clock

    def name(self):
        return self.NAME

    def short_name(self):
        # Slot 18: the empty-string stub 0x5d2ca10.
        return ""

    def is_instance_of(self, name):
        # 0x6202520: "Merge By TTL", Name(), or the slot-18 short name.
        if name == self.LEGACY_NAME:
            return True
        if name == self.name():
            return True
        return name != "" and name == self.short_name()

    def wrapped_operator(self):
        # Slot 17: 0x6200940 returns the wrapped pointer.
        return self.wrapped

    def prepare_options(self, config_options):
        """Slot 5: resolve a null clock via 0x5fcf430, then base PrepareOptions."""
        if self.clock is None:
            self.clock = config_options.resolve_clock()
        return True

    def validate_options(self):
        """Slot 6: error on a null wrapped operator or clock, else base ValidateOptions."""
        if self.wrapped is None:
            return (False,
                    "UserMergeOperator required by TtlMergeOperator")
        if self.clock is None:
            return (False, "SystemClock required by TtlMergeOperator")
        return (True, None)

    def full_merge_v2(self, key, existing_value, operands, logger):
        """0x6206610.  existing_value is None when the key is absent."""
        if existing_value is not None and len(existing_value) <= 3:
            logger.log_error(_err(
                36, "Could not remove timestamp from existing value."))
            return MergeResult(False, None)
        stripped = []
        for operand in operands:
            if len(operand) <= 3:
                logger.log_error(_err(
                    45, "Could not remove timestamp from operand value."))
                return MergeResult(False, None)
            stripped.append(strip_timestamp(operand))
        existing = (strip_timestamp(existing_value)
                    if existing_value is not None else None)
        ok, merged = self.wrapped.full_merge_v2(key, existing, stripped)
        if not ok:
            return MergeResult(False, None)
        try:
            now = self.clock.get_current_time()
        except ClockFailure:
            logger.log_error(_err(
                86, "Could not get current time to be attached internally "
                    "to the new value."))
            return MergeResult(False, None)
        return MergeResult(True, append_timestamp(merged, now))

    def partial_merge_multi(self, key, operands, logger):
        """0x6201c90.  Operands are walked in 0x200-byte (32-Slice) chunks."""
        stripped = []
        for i in range(0, len(operands), 32):
            for operand in operands[i:i + 32]:
                if len(operand) <= 3:
                    logger.log_error(_err(
                        108, "Could not remove timestamp from value."))
                    return MergeResult(False, None)
                stripped.append(strip_timestamp(operand))
        ok, merged = self.wrapped.partial_merge_multi(key, stripped)
        if not ok:
            return MergeResult(False, None)
        try:
            now = self.clock.get_current_time()
        except ClockFailure:
            logger.log_error(_err(
                126, "Could not get current time to be attached internally "
                     "to the new value."))
            return MergeResult(False, None)
        return MergeResult(True, append_timestamp(merged, now))


class WrappedCompactionFilter:
    """Interface for the wrapped CompactionFilter (vtable slot 19)."""

    def filter(self, level, key, existing_value):
        """Return KEEP (0) or REMOVE (1)."""
        raise NotImplementedError

    def filter_merge_operand(self, level, key, existing_value):
        """Slot 20; the base default returns False."""
        return False


class RecordingCompactionFilter(WrappedCompactionFilter):
    """Wrapped filter that records what it was called with."""

    def __init__(self, decision=KEEP, merge_operand=False):
        self.calls = []
        self.decision = decision
        self.merge_operand = merge_operand

    def filter(self, level, key, existing_value):
        self.calls.append(("filter", level, key, existing_value))
        return self.decision

    def filter_merge_operand(self, level, key, existing_value):
        self.calls.append(("filter_merge_operand", level, key,
                           existing_value))
        return self.merge_operand


class TtlCompactionFilter:
    """TtlCompactionFilter (vtable 0x64d9630, object size 0x40).

    Fields: +0x20 wrapped CompactionFilter*, +0x30 ttl (int),
    +0x38 SystemClock*.
    """

    NAME = "TtlCompactionFilter"
    LEGACY_NAME = "Delete By TTL"

    def __init__(self, wrapped, ttl, clock):
        self.wrapped = wrapped
        self.ttl = ttl
        self.clock = clock

    def name(self):
        return self.NAME

    def short_name(self):
        # Slot 18: the empty-string stub 0x5d2ca10.
        return ""

    def is_instance_of(self, name):
        # 0x6202440: "Delete By TTL", Name(), or the slot-18 short name.
        if name == self.LEGACY_NAME:
            return True
        if name == self.name():
            return True
        return name != "" and name == self.short_name()

    def wrapped_filter(self):
        # Slot 17: 0x62008e0 returns the wrapped pointer.
        return self.wrapped

    def prepare_options(self, config_options):
        """Slot 5: resolve a null clock via 0x5fcf430, then base PrepareOptions."""
        if self.clock is None:
            self.clock = config_options.resolve_clock()
        return True

    def validate_options(self):
        """Slot 6: error on a null clock, else base ValidateOptions."""
        if self.clock is None:
            return (False, "SystemClock required by TtlCompactionFilter")
        return (True, None)

    def filter(self, level, key, existing_value):
        """0x6203520.  Returns (decision, new_value, value_changed).

        new_value is the value to write back when value_changed is
        True; it carries the original timestamp re-appended.
        """
        if is_expired(existing_value, self.ttl, self.clock):
            return (REMOVE, None, False)
        if self.wrapped is None:
            return (KEEP, None, False)
        decision = self.wrapped.filter(
            level, key, strip_timestamp(existing_value))
        if decision != KEEP:
            return (REMOVE, None, False)
        # Wrapped filter kept the value but may have changed it:
        # the caller reports that through value_changed; here the
        # model takes the changed value as an argument instead.
        return (KEEP, None, False)

    def filter_with_change(self, level, key, existing_value,
                           changed_value):
        """Filter where the wrapped filter changed the value.

        changed_value is the wrapped filter's *new_value output
        (payload without a timestamp); the TTL filter re-appends the
        original value's timestamp and reports value_changed.
        """
        if is_expired(existing_value, self.ttl, self.clock):
            return (REMOVE, None, False)
        if self.wrapped is None:
            return (KEEP, None, False)
        decision = self.wrapped.filter(
            level, key, strip_timestamp(existing_value))
        if decision != KEEP:
            return (REMOVE, None, False)
        if changed_value is None:
            return (KEEP, None, False)
        return (KEEP,
                changed_value + existing_value[-TS_LEN:], True)

    def filter_v2(self, level, key, value_type, existing_value,
                  changed_value=None):
        """0x5d2e4a0.  Returns (decision, new_value, value_changed)."""
        if value_type == K_VALUE:
            # FilterV2 delegates to Filter (slot 0x98) for kValue:
            # expiry first, then the wrapped-null check.
            if is_expired(existing_value, self.ttl, self.clock):
                return (REMOVE, None, False)
            if self.wrapped is None:
                return (KEEP, None, False)
            decision = self.wrapped.filter(
                level, key, strip_timestamp(existing_value))
            if decision != KEEP:
                return (REMOVE, None, False)
            if changed_value is None:
                return (KEEP, None, False)
            return (CHANGE_VALUE,
                    changed_value + existing_value[-TS_LEN:], True)
        if value_type == K_MERGE_OPERAND:
            # Slot 20 (FilterMergeOperand) is the base default here,
            # which returns False -> kKeep.
            if self.wrapped is not None and self.wrapped.filter_merge_operand(
                    level, key, existing_value):
                return (REMOVE, None, False)
            return (KEEP, None, False)
        return (KEEP, None, False)

    def filter_v3(self, level, key, value_type, existing_value,
                  changed_value=None):
        """0x5d2f8a0.  kWideColumnEntity is kept; otherwise FilterV2."""
        if value_type == K_WIDE_COLUMN_ENTITY:
            return (KEEP, None, False)
        # Slot 21 (FilterV2) is the canonical base here, so FilterV3
        # falls through to the FilterV2 mapping.
        return self.filter_v2(level, key, value_type, existing_value,
                              changed_value)

    def ignore_snapshots(self):
        # Slot 24: the ret-1 stub 0x5df72f0.
        return True

    def filter_merge_operand(self):
        # Slot 20: the ret-0 stub 0x5d2ca30 (base default: false).
        return False

    def prepare_blob_output(self):
        # Slot 23: the ret-0 stub 0x5d2ca40 (BlobDecision::kKeep).
        return KEEP

    def is_stacked_blob_db_internal_compaction_filter(self):
        # Slot 25: the ret-0 stub 0x5d2ca50.
        return False


class WrappedCompactionFilterFactory:
    """Interface for the wrapped CompactionFilterFactory (slot 20)."""

    def create_compaction_filter(self, context):
        raise NotImplementedError


class RecordingCompactionFilterFactory(WrappedCompactionFilterFactory):
    def __init__(self, wrapped_filter=None):
        self.wrapped_filter = wrapped_filter
        self.calls = []

    def create_compaction_filter(self, context):
        self.calls.append(context)
        return self.wrapped_filter


class TtlCompactionFilterFactory:
    """TtlCompactionFilterFactory (vtable 0x64d9718, object size 0x40).

    Fields: +0x20 ttl (int), +0x28 SystemClock*,
    +0x30 shared_ptr<CompactionFilterFactory> (wrapped).
    """

    NAME = "TtlCompactionFilterFactory"

    def __init__(self, ttl, clock, wrapped_factory):
        self.ttl = ttl
        self.clock = clock
        self._wrapped = wrapped_factory

    def name(self):
        return self.NAME

    def short_name(self):
        # Slot 18: the empty-string stub 0x5d2ca10.
        return ""

    def is_instance_of(self, name):
        # Slot 16 is the shared default 0x5d2e770: Name() or the
        # slot-18 short name (empty name never matches).
        if name == "":
            return False
        if name == self.name():
            return True
        return name == self.short_name()

    def wrapped_factory(self):
        # Slot 17: 0x6200920 returns the wrapped pointer.
        return self._wrapped

    def prepare_options(self, config_options):
        """Slot 5: resolve a null clock via 0x5fcf430, then base PrepareOptions."""
        if self.clock is None:
            self.clock = config_options.resolve_clock()
        return True

    def validate_options(self):
        """Slot 6: error on a null clock, else base ValidateOptions."""
        if self.clock is None:
            return (False,
                    "SystemClock required by TtlCompactionFilterFactory")
        return (True, None)

    def create_compaction_filter(self, context):
        """0x6202ba0.  Returns a TtlCompactionFilter wrapping the
        factory's own filter, or None when the context has no filter
        factory (context+0x30 null)."""
        if context is None or context.get("filter_factory") is None:
            return None
        wrapped = self._wrapped.create_compaction_filter(context)
        return TtlCompactionFilter(wrapped, self.ttl, self.clock)
