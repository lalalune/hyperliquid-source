"""Python model of node #115 routine 0x5d52bb0 (RE-001 last-slot scan).

The routine takes a holder, a container and a count and returns an
int. The model takes the table entries directly (a list of
(low, high) qword pairs, indexed by table index) plus the two
fallback callables, because the binary's fallback callees
(0x5f6c740 and 0x5f6c300) are pinned by call shape only.

Entry call 0x60d5390(H+0x700) is recorded as an event; its result
is ignored by the binary, so the model ignores it too.
"""

ENTRY_CALL = 0x60D5390
FIRST_CALLEE = 0x5F6C740
SECOND_CALLEE = 0x5F6C300
MASK64 = (1 << 64) - 1


def _signed64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def last_slot_scan(count, entries, first, second):
    """Run the scan. Returns (result, events).

    count: signed 32-bit count from ecx.
    entries: list of (low, high) pairs; indices 1..count-1 must exist
        when count >= 2 (index 0 is never read).
    first(index): stands for 0x5f6c740(element, index).
    second(count): stands for 0x5f6c300(element, count).
    events: ("entry_call", address) then, per fallback round,
        ("first", index, result) and ("second", count, result).
    """
    events = [("entry_call", ENTRY_CALL)]
    if count <= 1:
        return count, events
    idx = count - 1
    while True:
        low, high = entries[idx]
        span = _signed64(high - low) >> 3
        if span > 0:
            return idx + 1, events
        a = first(idx) & MASK64
        b = second(count) & MASK64
        events.append(("first", idx, a))
        events.append(("second", count, b))
        if a < b:
            return idx + 1, events
        idx -= 1
        if idx == 0:
            return 1, events
