#!/usr/bin/env python3
"""Model of node #115 routine 0x5d5a9d0 (FDE 0x5d5a9d0..0x5d5ab57).

Shared-release pair:

1. Counted-array phase. The count lives at holder+0x00 and the
   element base pointer at holder+0x88, with a 0x10 stride and
   the control pointer at element+0x08. The loop decrements the
   count first, then releases the element at the new count, so
   the array drains from the last element down to the first,
   ending with count 0. A zero count at entry skips the phase.
   The base pointer is unchanged and the buffer is not freed.
2. Vector phase. The vector is (begin at holder+0x90, end at
   holder+0x98), same stride and control field. The loop walks
   forward from begin to end, releasing each element's control,
   then stores begin into end, logically emptying the vector
   while leaving its buffer in place. An empty vector skips the
   loop and leaves end unchanged.

Release shape (both phases). A null control is skipped. For a
live control, the count at control+0x08 is decremented: the
flag byte at 0x64ed290 selects the form — nonzero takes the
plain decrement, zero takes the atomic decrement. When the old
count is 1, the destroy helper 0x5d35070 is called with the
control in rdi. When the count is the sentinel 0x100000001,
control+0x08 is zeroed and the virtual slots 0x10 then 0x18
are called. Element+0x00 is never read.

Inputs are abstract: a control is None (null) or an integer
count. The flag argument is True when the flag byte is nonzero
(plain decrement) and False when it is zero (atomic decrement).
"""

DESTROY_HELPER = 0x5D35070
SENTINEL = 0x100000001


def release_control(count, flag_nonzero):
    """Ordered ops for one control release.

    count: the integer at control+0x08, or None for a null
    control. flag_nonzero: True for the plain decrement path,
    False for the atomic decrement path.
    """
    if count is None:
        return [("skip_null",)]
    if count == SENTINEL:
        return [("zero_count",), ("call_vtable_slot_0x10",),
                ("call_vtable_slot_0x18",)]
    form = "decrement_plain" if flag_nonzero else "decrement_atomic"
    ops = [(form, count)]
    if count == 1:
        ops.append(("call_destroy_helper", DESTROY_HELPER))
    return ops


def release_counted_array(count, controls, flag_nonzero):
    """Ordered ops for the counted-array phase plus the final count.

    controls: list in element order, one entry per element
    (None for a null control, else the control's count).
    Returns (ops, final_count).
    """
    ops = []
    remaining = count
    while remaining > 0:
        remaining -= 1
        ops.extend(release_control(controls[remaining], flag_nonzero))
    return ops, remaining


def release_vector(controls, flag_nonzero):
    """Ordered ops for the vector phase plus the end-reset marker.

    controls: list in element order (None for a null control,
    else the control's count). An empty list skips the loop and
    leaves end unchanged, so no reset marker is emitted.
    """
    ops = []
    for control in controls:
        ops.extend(release_control(control, flag_nonzero))
    if controls:
        ops.append(("reset_end_to_begin",))
    return ops


def release_holder(count, array_controls, vector_controls, flag_nonzero):
    """Ordered ops for one holder: both phases, end to end."""
    ops, final_count = release_counted_array(count, array_controls,
                                             flag_nonzero)
    ops.extend(release_vector(vector_controls, flag_nonzero))
    return ops, final_count
