#!/usr/bin/env python3
"""Model of node #115 routine 0x5d590c0 (FDE 0x5d590c0..0x5d591c1).

Shared-release array teardown: for each 0x40-byte element in the holder
range [holder+0x00, holder+0x08), release the shared control block at
element+0x38 with libstdc++ _Sp_counted_base release semantics, then
dispose the string at element+0x08 with the short-form rule; finally
free the holder buffer (begin, [holder+0x10] - begin) via a tail jump
to the sized-delete PLT, or return plainly when the buffer is null.

The single_threaded flag selects the decrement shape only (plain
decrement when the __libc_single_threaded byte is nonzero, LOCK XADD
otherwise); observable results are identical in both modes.

Preconditions (matching the binary's assumptions): the element range
is valid, or the buffer is null with an empty range. A null buffer
with a non-empty range is not modelled (the binary would dereference
the null begin).
"""

MASK32 = 0xFFFFFFFF
SENTINEL = 0x100000001  # use == 1 and weak == 1 as one 64-bit value


class Control:
    """A shared control block: low 32 bits use count, high 32 weak."""

    def __init__(self, use, weak):
        self.use = use & MASK32
        self.weak = weak & MASK32
        self.disposed = False
        self.destroyed = False
        self.destroyer_called = False  # helper 0x5d35070 ran

    def combined(self):
        return (self.weak << 32) | self.use


def release_control(ctrl, single_threaded=True):
    """Release one control block; returns the path taken as op names."""
    ops = []
    if ctrl.combined() == SENTINEL:
        # Zero the whole count, then dispose virtual (+0x10) and
        # destroy virtual (+0x18) directly. The helper is NOT used.
        ctrl.use = 0
        ctrl.weak = 0
        ctrl.disposed = True
        ctrl.destroyed = True
        ops.append("sentinel_dispose_destroy")
        return ops
    old_use = ctrl.use
    ctrl.use = (ctrl.use - 1) & MASK32
    if old_use == 1:
        # Helper 0x5d35070: dispose virtual, weak-count decrement,
        # destroy virtual only when the old weak count was 1. That
        # arm cannot fire from here: (use, weak) == (1, 1) is
        # intercepted by the sentinel path above, so any old weak
        # seen here differs from 1.
        ctrl.destroyer_called = True
        ctrl.disposed = True
        old_weak = ctrl.weak
        ctrl.weak = (ctrl.weak - 1) & MASK32
        ops.append("destroyer_dispose_weakdec")
        if old_weak == 1:  # unreachable from this routine; kept explicit
            ctrl.destroyed = True
            ops.append("destroyer_destroy")
    else:
        ops.append("decrement")
    return ops


def dispose_string(string):
    """string is ("short",) or ("heap", capacity). Returns the op."""
    if string[0] == "short":
        return "skip_short_string"
    return ("free_string", string[1] + 1)


def release_array(holder, single_threaded=True):
    """holder: {"elements": [{"control": Control|None,
    "string": ("short",)|("heap", cap)}], "buffer": None|size}.
    Returns the ordered op list; mutates the control blocks."""
    elements = holder["elements"]
    if holder["buffer"] is None:
        if elements:
            raise ValueError("null buffer with a non-empty range")
        return ["return_null_buffer"]
    ops = []
    for index, element in enumerate(elements):
        ctrl = element["control"]
        if ctrl is None:
            ops.append((index, "skip_null_control"))
        else:
            for op in release_control(ctrl, single_threaded):
                ops.append((index, op))
        string_op = dispose_string(element["string"])
        if isinstance(string_op, tuple):
            ops.append((index, string_op[0], string_op[1]))
        else:
            ops.append((index, string_op))
    ops.append(("free_buffer", holder["buffer"]))
    return ops
