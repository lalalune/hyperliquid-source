"""Python model of the RE-001 lazy-cache adapter 0x5d548a0 (node #115).

Models only the established semantics from
research/work-items/RE-001-lazy-cache-adapter-548a0-115/:
the adapter forwards its holder's +0x320 cache slot and +0x540 value
(via the getter 0x5d54890) to the cache routine 0x61bcde0 and returns
its first argument unchanged. The cache routine, under a lock pair
(0x606ca40 acquire / 0x60d52f0 release, call-shape only), either
reports the cached state (slot +0x60 non-null: out+0 dword 11, out+4
word 0, out+8 qword 0) or, on the fresh path, copies a 25-byte key
from X into the slot, builds a 0x30-byte record with 0x61bc290
(G, X[0..31], [Y], zeroing [Y]), installs it at slot +0x60, sets the
present byte at slot +0x68, and calls the notifier 0x61bca30
(call-shape only: the model records the call but does not claim what
the notifier writes into out). The cleanup routine 0x61bcda6 frees
the fresh record (when allocated) and releases the lock before
resuming unwinding.
"""

RECORD_SIZE = 0x30
KEY_SIZE = 25


class Out:
    """The out record; writes are tracked per offset."""

    def __init__(self, name):
        self.name = name
        self.writes = {}

    def write_dword(self, offset, value):
        self.writes[offset] = ("dword", value)

    def write_word(self, offset, value):
        self.writes[offset] = ("word", value)

    def write_qword(self, offset, value):
        self.writes[offset] = ("qword", value)


class Record:
    """One 0x30-byte record built by 0x61bc290."""

    def __init__(self, g, blob, moved):
        self.g = g
        self.blob = bytes(blob)
        self.moved = moved


class CacheSlot:
    """The cache slot object S at holder+0x320."""

    def __init__(self):
        self.key = bytearray(KEY_SIZE)
        self.record = None
        self.present = 0


class Holder:
    """The holder H: +0x320 cache slot, +0x540 getter value."""

    def __init__(self, g540):
        self.cache = CacheSlot()
        self.g540 = g540


def getter(holder):
    """The getter 0x5d54890: return [H+0x540]."""
    if holder is None:
        raise ValueError("null holder")
    return holder.g540


def build_record(g, x, y, events):
    """The builder 0x61bc290: new+0 = G, new+8..0x27 = X[0..31],
    new+0x28 = [Y], then [Y] = 0. y is a one-element list modelling
    the qword at Y, so the zeroing is observable."""
    if len(x) < 32:
        raise ValueError("X shorter than 32 bytes")
    if len(y) != 1:
        raise ValueError("Y must hold exactly one qword")
    record = Record(g, x[:32], y[0])
    y[0] = 0
    events.append(("build_record", record))
    return record


def cache_ensure(out, slot, g, x, y, notifier, events):
    """The cache routine 0x61bcde0. notifier is a callable
    (out, record) standing in for 0x61bca30; the model records its
    call but claims nothing about what it writes into out."""
    if slot is None or out is None:
        raise ValueError("null slot or out")
    events.append(("acquire",))
    if slot.record is not None:
        out.write_dword(0x00, 11)
        out.write_word(0x04, 0)
        out.write_qword(0x08, 0)
        events.append(("release",))
        return out
    if len(x) < KEY_SIZE:
        raise ValueError("X shorter than the 25-byte key")
    slot.key[0:16] = x[0:16]
    slot.key[9:25] = x[9:25]
    events.append(("alloc", RECORD_SIZE))
    record = build_record(g, x, y, events)
    slot.record = record
    slot.present = 1
    events.append(("notifier", record))
    if notifier is not None:
        notifier(out, record)
    events.append(("release",))
    return out


def cleanup(record, events):
    """The cleanup routine 0x61bcda6. With a record (exception after
    allocation) it frees the record first, then releases the lock;
    without one it only releases the lock. Either way unwinding
    resumes afterwards."""
    if record is not None:
        events.append(("free_record", RECORD_SIZE))
    events.append(("release",))
    events.append(("resume",))


def adapter(out, holder, x, y, notifier, events):
    """The adapter 0x5d548a0: forward holder fields to the cache
    routine and return out unchanged."""
    if holder is None:
        raise ValueError("null holder")
    slot = holder.cache
    g = getter(holder)
    cache_ensure(out, slot, g, x, y, notifier, events)
    return out
