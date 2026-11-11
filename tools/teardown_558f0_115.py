"""Python model of node #115 routine 0x5d558f0: guarded teardown.

The routine takes one object pointer, returns nothing, and frees six
fields in a fixed order. It writes nothing back to the object. The
model records the observable frees and terminal events in order; it
does not model the contents of the fields or the internals of the
release helper 0x5d350c0 (pinned by call shape only; its contract is
established in the RE-001 derived-destructor packet for the same
address).

Phase order (see the packet README for the evidence):
  1. +0xc0 refcounted pointer: null skips, else release via helper.
  2. +0x98 cell: null skips; first qword nonzero terminates the
     process (nothing after runs); first qword zero frees the cell
     with the sized delete passing (cell, 8).
  3. +0x40 condition variable: destroyed unconditionally through the
     wrapper 0x60d5470; return codes 0, 16 and 110 return, any other
     code prints a diagnostic and aborts (nothing after runs).
  4. +0x38 array: null skips, else delete[].
  5. +0x28 array: null skips, else delete[].
  6. +0x18 array: null skips, else delete[] (via a tail jump; the
     distinction from a call is not observable in the event list).
"""


def teardown(ref_c0, cell_first, cond_code, arr38, arr28, arr18):
    """Return the ordered list of observable events.

    ref_c0, arr38, arr28, arr18 are None for null, otherwise opaque
    identifiers. cell_first is None for a null cell, otherwise the
    cell's first qword. cond_code is the wrapper's destroy return
    code. An event is ("release", ref), ("sized_delete", "cell98", 8),
    ("terminate",), ("cond_destroy", code),
    ("cond_destroy_abort", code) or ("delete_array", field_name).
    """
    events = []
    if ref_c0 is not None:
        events.append(("release", ref_c0))
    if cell_first is not None:
        if cell_first != 0:
            events.append(("terminate",))
            return events
        events.append(("sized_delete", "cell98", 8))
    if cond_code in (0, 16, 110):
        events.append(("cond_destroy", cond_code))
    else:
        events.append(("cond_destroy_abort", cond_code))
        return events
    for name, arr in (("38", arr38), ("28", arr28), ("18", arr18)):
        if arr is not None:
            events.append(("delete_array", name))
    return events
