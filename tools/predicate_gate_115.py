"""Python model of node #115's predicate gate 0x5f132a0/0x5f132c0.

Implements the semantics pinned by research/work-items/RE-001-predicate-gate-115:
the flag-gated compare at 0x5f132a0, the two-stage gate at 0x5f132c0 that
tail-delegates to it, the getter at 0x5eeb460 that exposes the compare,
and the branch direction each confirmed consumer takes on the result.

A record is a dict with keys: link_value (unsigned 64-bit at the linked
record's +0x10, or None when the link is absent), value (signed 32-bit at
+0x10), threshold (signed 32-bit at +0x04), flag (unsigned byte at +0x15).
"""

MASK64 = (1 << 64) - 1


def _s32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def flag_compare(record):
    """The 0x5f132a0 window. Returns a byte value (0..255)."""
    flag = record["flag"] & 0xFF
    value = _s32(record["value"])
    threshold = _s32(record["threshold"])
    if flag != 0 and value > 0:
        return flag
    return 1 if threshold <= value else 0


def gate(record):
    """The 0x5f132c0 window. Returns a byte value (0..255)."""
    if record["link_value"] is None:
        raise ValueError("gate dereferences record + 0x08 with no guard")
    own64 = _s32(record["value"]) % (1 << 64)
    if own64 != (record["link_value"] & MASK64):
        return 1
    return flag_compare(record)


def getter(record):
    """The 0x5eeb460 getter: (stored_byte, return_value)."""
    return flag_compare(record) & 0xFF, 1


def branch_gate_caller_5e8d1e6(result):
    """0x5e8d1e6 consumer: nonzero -> skip path, zero -> continue."""
    return "skip" if result != 0 else "continue"


def branch_compare_caller_5ddafe7(result):
    """0x5ddafe7 consumer: zero -> jump away, nonzero -> proceed."""
    return "proceed" if result != 0 else "away"


def branch_compare_caller_5de860e(result):
    """0x5de860e consumer: zero -> jump away, nonzero -> proceed."""
    return "proceed" if result != 0 else "away"
