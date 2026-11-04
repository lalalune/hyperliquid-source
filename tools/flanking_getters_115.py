"""Python model of node #115's flanking getters 0x5eeb220/0x5eeb3a0/0x5eeb3c0.

Implements the semantics pinned by
research/work-items/RE-001-flanking-getters-115. The three getters are
the still-unmapped getters flanking the mapped 0x5eeb250..0x5eeb741 run:
one virtual-call predicate getter, one stub-delegating getter, and one
refresh-then-signed-field getter. Each stores to *out and returns 1
unconditionally, with no null check anywhere in the binary.

State shapes (all plain dicts, no binary layout):

- The virtual getter takes (out, obj): obj is ``{"vptr": {"slot478":
  callable}}`` mirroring the qword at obj + 0x0 (the vptr) and the
  slot at vptr + 0x478. The slot is called with obj, mirroring the
  binary passing rdx (obj) in rdi, and only its low byte survives
  (movzbl), so *out is the low byte of the slot's return.
- The delegating getter takes (outer, out, target): outer is
  ``{"field788": member}`` mirroring the qword at outer + 0x788, and
  member is ``{"field28": sub}`` mirroring the qword at member + 0x28.
  ``target`` is a callable modelling the 0x5f90da0 computation by
  contract (its full walk is not modelled here); it is called with
  sub and its full 64-bit return is stored.
- The refresh getter takes (out, obj, refresh): obj is ``{"field700":
  refresh_arg, "field1440": int}`` mirroring the qwords at obj + 0x700
  and obj + 0x1440. ``refresh`` is a callable modelling 0x60d5390 by
  contract; it is called with the +0x700 value and its return is
  ignored, then *out is the sign-extended 32-bit field at +0x1440.

``out`` is modelled as a one-element list, mirroring the rsi pointer
the getters store to.

Model-side notes (not binary behavior, stated explicitly): the binary
has no null checks and would fault on a dangling pointer; a missing
field raises KeyError, mirroring a fault. A 64-bit value outside the
unsigned 64-bit range raises ValueError, and a refresh-field value
outside the signed 32-bit range raises ValueError, mirroring that the
binary fields are exactly that wide. The delegating getter's target
and the refresh getter's refresh are caller-supplied stand-ins for
by-contract callees, not claims about those callees' internals.
"""

MASK64 = (1 << 64) - 1
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1


def _u64(value):
    if not 0 <= value <= MASK64:
        raise ValueError("field value %r is outside unsigned 64-bit range" % (value,))
    return value


def _signed32(value):
    if not INT32_MIN <= value <= INT32_MAX:
        raise ValueError("field value %r is outside signed 32-bit range" % (value,))
    return value


def virtual_getter(out, obj):
    """Getter 0x5eeb220: *out = low_byte(virtual_slot_0x478(obj))."""
    slot = obj["vptr"]["slot478"]
    out[0] = slot(obj) & 0xFF
    return 1


def delegating_getter(outer, out, target):
    """Getter 0x5eeb3a0 via stub 0x5d8c9c0: *out = target([member + 0x28])."""
    member = outer["field788"]
    out[0] = _u64(target(member["field28"]))
    return 1


def refresh_field_getter(out, obj, refresh):
    """Getter 0x5eeb3c0: refresh(obj + 0x700); *out = sign_extend32([obj + 0x1440])."""
    refresh(obj["field700"])
    out[0] = _signed32(obj["field1440"])
    return 1
