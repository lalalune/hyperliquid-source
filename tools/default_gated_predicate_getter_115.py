"""Python model of node #115's default-gated predicate getter 0x5eeb7a0
and its default implementation 0x5d89610.

Implements the semantics pinned by
research/work-items/RE-001-default-gated-predicate-getter-115. The
getter takes (outer, out): it loads the member at [outer + 0x788],
loads the virtual object at [member + 0x950], loads the virtual slot
at [vtable + 0x28], and compares it against the default
implementation's address (the RELATIVE addend of the .got slot at
0x64ed2d0). On the default arm it stores 0 without calling anything
and returns 1; on the override arm it calls the slot with (obj,
[member + 0x30] + 0x40), stores the movzbl-masked low byte of the
return, and returns 1. Both arms return 1 unconditionally, and there
is no null check anywhere.

State shapes (all plain dicts, no binary layout):

- An outer object is ``{"field788": member}`` mirroring the qword
  at outer + 0x788, and a member object is ``{"field950": obj,
  "field30": int}`` mirroring the qwords at member + 0x950 and
  member + 0x30. ``out`` is modelled as a one-element list,
  mirroring the rsi pointer the getter stores to.
- A virtual object is ``{"slot": slot}`` where slot is either the
  ``DEFAULT_SLOT`` sentinel (mirroring the default implementation
  0x5d89610) or a callable taking (obj, arg) and returning an int,
  mirroring an overriding implementation.

Model-side notes (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer;
a missing field raises KeyError, mirroring a fault. The override
body varies by class and is supplied by the caller as a callable;
only its calling convention and the low-byte masking are pinned.
The argument [member + 0x30] + 0x40 wraps at 64 bits, as the
binary's addq does.
"""

MASK64 = (1 << 64) - 1

#: Sentinel for the default implementation 0x5d89610 (xor eax, eax;
#: ret). The binary compares the slot against the .got slot at
#: 0x64ed2d0, whose RELATIVE addend is 0x5d89610.
DEFAULT_SLOT = "default-0x5d89610"


def default_predicate(obj, arg):
    """Default implementation 0x5d89610: returns 0, ignores args."""
    return 0


def predicate_getter(outer, out):
    """Getter 0x5eeb7a0: *out = default-gated predicate, return 1.

    Default arm: slot is DEFAULT_SLOT, so *out = 0 with no call.
    Override arm: *out = movzbl(override(obj, [member + 0x30] + 0x40)).
    Always returns 1.
    """
    member = outer["field788"]
    obj = member["field950"]
    slot = obj["slot"]
    if slot is DEFAULT_SLOT:
        out[0] = 0
        return 1
    arg = (member["field30"] + 0x40) & MASK64
    out[0] = slot(obj, arg) & 0xFF
    return 1
