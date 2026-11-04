"""Model of node #115 in-memory stats history size, 0x5d525d0 (RE-001).

The routine estimates the byte size of an in-memory stats history
held by a database object, and its two call sites log the result as
"[Pre-GC] In-memory stats history size: %zu bytes, slice count: %zu"
and the matching "[Post-GC]" line while a trim loop erases the
oldest slices until the estimate falls under a limit.

Pinned layout (see
research/work-items/RE-001-stats-history-size-525d0-115/):

- Database object: the history map header is embedded at +0xca8
  (color +0xca8, parent +0xcb0, leftmost +0xcb8, rightmost +0xcc0)
  with the slice count at +0xcc8. The routine reads only +0xcb8
  (the oldest slice node) and +0xcc8 (the slice count).
- Outer node (0x58 bytes): RB node base +0x00..+0x1f, ordered key
  at +0x20, an unpinned 8-byte field at +0x28, and an embedded
  RB-tree header at +0x30 (color +0x30, parent +0x38, leftmost
  +0x40, rightmost +0x48) with its entry count at +0x50. The
  routine walks the embedded tree of the OLDEST outer node only:
  first entry = [oldest + 0x40], end sentinel = oldest + 0x30.
- Inner entry: RB node base +0x00..+0x1f, key string at +0x20
  (data pointer +0x20, size +0x28, inline buffer / capacity
  +0x30). The routine reads only the data pointer and the
  +0x30 slot: data == entry + 0x30 means the string is stored
  inline (SSO); otherwise +0x30 holds the heap capacity.

Pinned arithmetic, reproduced exactly:

- Slice count zero returns 48 (0x30), not zero.
- Otherwise the result is slice_count * (56 + sum over the oldest
  slice's entries), where each entry contributes 55 when its key
  string is SSO, or capacity + 40 when it is heap-allocated.
  The constants decompose as 55 = 40 + 15 (the SSO buffer holds
  at most 15 bytes), which is recorded as inference: the binary
  only shows the constants 55 and 40, not the decomposition.

The model does not guess why the estimate multiplies the oldest
slice's sum by the slice count instead of summing every slice;
it reproduces the observed arithmetic, and the packet records
that reading as an open question. The trim loop below mirrors
the single consumer: log the Pre-GC line, erase the oldest
slice while the estimate exceeds the limit and slices remain,
then log the Post-GC line.
"""

FILE_STRING = "db/db_impl/db_impl.cc"
PRE_GC_FORMAT = "[%s:976] [Pre-GC] In-memory stats history size: %zu bytes, slice count: %zu"
POST_GC_FORMAT = "[%s:985] [Post-GC] In-memory stats history size: %zu bytes, slice count: %zu"

EMPTY_RESULT = 0x30
BASE_PER_SLICE = 0x38
SSO_ENTRY = 0x37
HEAP_FIXED = 0x28
SSO_CAPACITY = 15


class Entry:
    """One entry of a slice's embedded map: a key string."""

    def __init__(self, sso, capacity=0):
        self.sso = bool(sso)
        if not self.sso:
            if not isinstance(capacity, int) or capacity < 0:
                raise ValueError("heap capacity must be a non-negative int")
            self.capacity = capacity
        else:
            # An SSO string's +0x30 slot holds buffer bytes, not a
            # capacity; the binary never reads a capacity for it.
            self.capacity = None

    def contribution(self):
        if self.sso:
            return SSO_ENTRY
        return self.capacity + HEAP_FIXED


class Slice:
    """One outer node: an ordered list of inner entries."""

    def __init__(self, entries=()):
        self.entries = list(entries)


class History:
    """The history object: outer nodes in key order, oldest first."""

    def __init__(self, slices=()):
        self.slices = list(slices)

    @property
    def slice_count(self):
        return len(self.slices)


def oldest_slice_sum(history):
    """56 plus the per-entry sum over the oldest slice's entries."""
    if not history.slices:
        return BASE_PER_SLICE
    total = BASE_PER_SLICE
    for entry in history.slices[0].entries:
        total += entry.contribution()
    return total


def stats_history_size(history):
    """The routine's return value, exactly as the binary computes it."""
    count = history.slice_count
    if count == 0:
        return EMPTY_RESULT
    return count * oldest_slice_sum(history)


def pre_gc_log_line(history):
    size = stats_history_size(history)
    return "[%s:976] [Pre-GC] In-memory stats history size: %d bytes, slice count: %d" % (
        FILE_STRING, size, history.slice_count)


def post_gc_log_line(history):
    size = stats_history_size(history)
    return "[%s:985] [Post-GC] In-memory stats history size: %d bytes, slice count: %d" % (
        FILE_STRING, size, history.slice_count)


def trim_history(history, limit):
    """Mirror the consumer: Pre-GC log, erase oldest slices while
    the estimate exceeds limit and slices remain, Post-GC log.
    Returns the two log lines; history is mutated in place."""
    lines = [pre_gc_log_line(history)]
    while history.slices and stats_history_size(history) > limit:
        history.slices.pop(0)
    lines.append(post_gc_log_line(history))
    return lines
