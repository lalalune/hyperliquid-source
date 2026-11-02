"""Python model of node #94's WAL flush phase A, window 0x50e9410.

Faithful to research/work-items/RE-001-wal-flush-phase-a-94/records.json:
phase A of the WAL flush driver (mapped by PR #1892) decides whether
one looked-up object joins the flush collection, appends it when the
gates pass, and otherwise returns silently. The lookup callee
0x4fec940, the overflow grow helper 0x4fc75e0 and the log callee
0x522ea30 are modelled by their call contracts only; their internals
are not pinned here.

Collection layout (the driver collection, see PR #1892): count at
+0x00 (the inline element count, 0..8), an inline-array pointer at
+0x48 (8 slots), and an overflow vector at +0x50/+0x58/+0x60
(begin/end/capacity). Total elements = inline count + overflow count.
"""

LOG_MESSAGE = ("[%s:1980] Force flushing stats CF with automated flush "
               "to avoid holding old logs")
LOG_FILE = "db/db_impl/db_impl_write.cc"
MASK64 = (1 << 64) - 1
INLINE_SLOTS = 8


class Collection:
    """The flush collection: inline slots plus an overflow vector."""

    def __init__(self, inline=None, overflow=None, overflow_capacity=0):
        self.inline = list(inline or [])
        self.overflow = list(overflow or [])
        self.overflow_capacity = overflow_capacity

    @property
    def inline_count(self):
        return len(self.inline)

    @property
    def total(self):
        return len(self.inline) + len(self.overflow)

    def elements(self):
        return list(self.inline) + list(self.overflow)

    def append(self, item, grow_log=None):
        """Append exactly as the window does.

        Inline while the inline count is at most 7; otherwise append
        to the overflow vector, calling the grow helper first when
        the overflow end already equals its capacity.
        """
        if len(self.inline) <= 7:
            self.inline.append(item)
        else:
            if len(self.overflow) >= self.overflow_capacity:
                if grow_log is not None:
                    grow_log.append("grow_overflow")
                self.overflow_capacity = max(self.overflow_capacity * 2,
                                             len(self.overflow) + 1)
            self.overflow.append(item)


def flush_phase_a(db_flag_4c9, collection, lookup_result, lookup_key,
                  lookup_chain_ok, list_items, db_name=None, log=None,
                  grow_log=None):
    """Run phase A. Returns an outcome string.

    db_flag_4c9: byte at db +0x4c9 (nonzero enables the phase).
    collection: a Collection.
    lookup_result: the 0x4fec940 result, or None when it is null.
    lookup_key: the lookup result's +0x948 field (unsigned 64-bit).
    lookup_chain_ok: whether the result's +0x8e8 -> +0xc18 chain is
        non-null (the window returns when it is null).
    list_items: (node, key) pairs for the db list nodes, in walk
        order, where key is the node's +0x948 field. A node identical
        to the lookup result is skipped by the binary's loop (it
        compares node pointers first), so it never blocks the append.
    db_name: the db +0x360 name passed to the log call on append.
    log: optional list receiving the level-1 log record on append.
    grow_log: optional list receiving a grow-helper record.
    """
    if collection.total == 0:
        return "noop_empty"
    if not db_flag_4c9:
        return "noop_flag"
    if lookup_result is None:
        return "noop_lookup_null"
    if not lookup_chain_ok:
        return "noop_chain_null"
    if lookup_result in collection.elements():
        return "noop_present"
    lookup_key &= MASK64
    for node, key in list_items:
        if node == lookup_result:
            continue
        if lookup_key >= (key & MASK64):
            return "noop_not_smallest"
    collection.append(lookup_result, grow_log=grow_log)
    if log is not None:
        log.append((1, db_name, LOG_MESSAGE, LOG_FILE))
    return "appended"
