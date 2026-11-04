"""Python model of node #115's pipeline dispatcher at 0x5f88550.

RE-001 work item: research/work-items/RE-001-pipeline-dispatch-115/.
The dispatcher takes (obj, arg, flag) in (rdi, rsi, rdx) and returns
whatever the prologue returns. Only the low byte of rdx participates
in the branch: a zero flag byte goes straight to the prologue, a
nonzero flag byte runs the two-phase filtered accumulation scan first
and then the prologue. The scan takes only the object pointer (its own
semantics are the RE-001-two-phase-filtered-accum-115 item, not
re-claimed here); the prologue is the RE-001-pipeline-trim-115 item's
0x5f884b0 function, likewise referenced, not re-claimed.
"""

MASK64 = (1 << 64) - 1


def dispatch(obj, arg, flag_value, scan, prologue):
    """Route one pipeline object through the scan and the prologue.

    obj: a mapping with the qword at obj+0x10, keyed by the integer
    offset 0x10. Raises ValueError when that field is absent, so a
    caller cannot silently model a partially known object.
    arg: the dispatcher's second argument, passed through to the
    prologue unchanged as its third argument.
    flag_value: the dispatcher's third argument; only its low byte
    decides the branch, matching the native test of dl.
    scan: a callable taking obj, standing for the 0x5f77330 scan;
    called exactly once, before the prologue, when the flag byte is
    nonzero, and never otherwise. Its return value is discarded.
    prologue: a callable taking (obj, obj_delta, arg2, arg), where
    obj_delta is 0x40 (the prologue's object base is obj+0x40) and
    arg2 is (obj[0x10] + 0x368) mod 2**64. Its return value is the
    dispatcher's return value.
    """
    if 0x10 not in obj:
        raise ValueError("obj is missing field 0x10")
    if flag_value & 0xFF != 0:
        scan(obj)
    arg2 = (obj[0x10] + 0x368) & MASK64
    return prologue(obj, 0x40, arg2, arg)
