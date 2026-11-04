"""Model of node #115 routine 0x5d50400: copy the active
reference-counted handle out of a two-slot holder.

Holder layout (byte offsets, from the routine itself):

* slot A at +0x00: a 16-byte (pointer, control) pair.
* selector pointer at +0x10: null, or pointing at an object whose
  byte at +0x68 selects the slot.
* slot B at +0x20: a 16-byte (pointer, control) pair, same shape.

Selection: selector null -> slot A; selector flag byte 0 -> slot A;
selector flag byte non-zero -> slot B. The copy is a verbatim
16-byte copy; the routine returns the destination pair and does NOT
release the destination's previous pair (callers pass fresh
temporaries). If the copied control block is non-null, its 32-bit
count at control +0x08 increases by exactly 1; the binary uses a
lock-prefixed add when the global byte at 0x64ed290 is 0 and a plain
add otherwise. The model records which form applies but both forms
have the same observable effect on the count, so the count update
is identical either way.

The model is deliberately data-only: pointers are opaque tokens and
control blocks are objects carrying a count. It never dereferences
a dangling pointer, and it raises on malformed model inputs (a
selector flag outside a byte, a non-integer global byte) as a model
safety property, not a binary claim.
"""


class ControlBlock:
    """A control block carrying the count at control +0x08."""

    def __init__(self, count=0):
        self.count = count


class Selector:
    """The selector object: only its byte at +0x68 is read."""

    def __init__(self, flag):
        if not isinstance(flag, int) or isinstance(flag, bool):
            raise TypeError("flag must be an integer byte")
        if flag < 0 or flag > 255:
            raise ValueError("flag must fit in one byte")
        self.flag = flag


class Holder:
    """Two handle slots plus an optional selector.

    A handle is a (pointer, control) pair; pointer is an opaque
    token, control is a ControlBlock or None.
    """

    def __init__(self, slot_a, selector, slot_b):
        self.slot_a = slot_a
        self.selector = selector
        self.slot_b = slot_b


def copy_active_handle(holder, global_byte=0):
    """Copy the active handle, following routine 0x5d50400.

    Returns (pointer, control, add_form) where add_form is "lock"
    when the global byte is 0, "plain" when it is non-zero, and
    None when no count was incremented (copied control is None).
    The caller's destination pair is replaced by the returned pair;
    the old destination pair is not released.
    """
    if not isinstance(global_byte, int) or isinstance(global_byte, bool):
        raise TypeError("global_byte must be an integer byte")
    if global_byte < 0 or global_byte > 255:
        raise ValueError("global_byte must fit in one byte")
    if holder.selector is None or holder.selector.flag == 0:
        pointer, control = holder.slot_a
    else:
        pointer, control = holder.slot_b
    if control is None:
        return pointer, control, None
    control.count += 1
    return pointer, control, ("lock" if global_byte == 0 else "plain")
