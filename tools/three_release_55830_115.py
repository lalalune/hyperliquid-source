"""Python model of the node #115 three-release routine at 0x5d55830
(RE-001 work item) and its shared release helper pair.

The routine takes one object pointer in rdi and releases, in order,
the refcounted pointers at object +0x28, +0x18 and +0x08. A null
pointer is skipped; a non-null pointer is passed to the shared
release helper 0x5d350c0. The first two releases are direct calls;
the third is a tail jump, so the helper's return is the routine's
return when the +0x08 pointer is non-null. The routine writes
nothing back to the object: the three fields keep their pointers.

The helper pair works on a packed 64-bit count at target +0x08,
viewed as two 32-bit halves (low at +0x08, high at +0x0c):

  * low half (0x5d350c0): if the whole qword equals 0x100000001,
    the count is zeroed, vtable slot 0x10 is called, and control
    tail-jumps to vtable slot 0x18. Otherwise the low half is
    decremented -- with a plain store when the guard byte at
    0x64ed290 is nonzero, with a locked xadd when it is zero --
    and if the old low half was 1 (the low half reached zero),
    control passes to the high-half fragment.
  * high half (0x5d35070, its own FDE): vtable slot 0x10 is called,
    the high half is decremented (plain or locked by the same
    guard byte), and if the old high half was 1, control
    tail-jumps to vtable slot 0x18; otherwise it returns.

So slot 0x10 (the destructor body) runs when the low half reaches
zero, and slot 0x18 (the deleting destructor) runs only when the
high half also reaches zero -- or immediately on the packed
0x100000001 sentinel, where both halves are 1.

A refcounted target is a ``RefCounted`` with ``low`` and ``high``
halves and a ``name`` used only to label events. An event is
``("destructor", name)`` for a slot-0x10 call or ``("deleter",
name)`` for a slot-0x18 tail jump. The plain and locked decrement
paths produce identical observable events.
"""

FIELDS = ("+0x28", "+0x18", "+0x08")

SENTINEL = 0x100000001


class RefCounted:
    """One refcounted target: two 32-bit count halves."""

    def __init__(self, name, low, high):
        self.name = name
        self.low = low
        self.high = high


def release(ref, events):
    """Apply the helper pair to one refcounted target."""
    if ref.low == 0 and ref.high == 0:
        raise ValueError(f"{ref.name}: release of a zero-count target")
    if (ref.high << 32) | ref.low == SENTINEL:
        ref.low = 0
        ref.high = 0
        events.append(("destructor", ref.name))
        events.append(("deleter", ref.name))
        return
    old_low = ref.low
    ref.low = (ref.low - 1) & 0xFFFFFFFF
    if old_low == 1:
        events.append(("destructor", ref.name))
        old_high = ref.high
        ref.high = (ref.high - 1) & 0xFFFFFFFF
        if old_high == 1:
            events.append(("deleter", ref.name))


def teardown(holder):
    """Simulate the routine; return the ordered destructor/deleter events.

    ``holder`` maps each field in FIELDS to a RefCounted or None.
    The holder mapping is never mutated: pointers are not cleared.
    """
    events = []
    for field in FIELDS:
        ref = holder[field]
        if ref is not None:
            release(ref, events)
    return events
