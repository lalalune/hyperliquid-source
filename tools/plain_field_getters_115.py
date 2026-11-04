"""Python model of node #115's plain field getters 0x5eeb250/0x5eeb270/
0x5eeb2f0/0x5eeb320/0x5eeb350/0x5eeb380.

Implements the semantics pinned by
research/work-items/RE-001-plain-field-getters-115. Each getter takes
(outer, out): it loads the member at [outer + 0x788], then either reads
a field of a second-level sub-object or, for getter F, a field of the
member itself, stores it to *out, and returns 1 unconditionally.
Getter A reads a signed 32-bit field and sign-extends it (movslq);
the other five read 64-bit fields.

State shapes (all plain dicts, no binary layout):

- An outer object is ``{"field788": member}`` mirroring the qword
  at outer + 0x788. A member object is ``{"field30": sub30,
  "field8e8": sub8e8, "field928": int}`` mirroring the qwords at
  member + 0x30, member + 0x8e8 and member + 0x928. The +0x30
  sub-object is ``{"fieldb30": int, "field1008": int}`` and the
  +0x8e8 sub-object is ``{"fieldcd0": int, "fielda70": int,
  "fielda78": int}``. ``out`` is modelled as a one-element list,
  mirroring the rsi pointer the getter stores to.

Model-side notes (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer;
a missing field raises KeyError, mirroring a fault. A 64-bit field
value outside the unsigned 64-bit range raises ValueError, and
getter A's field outside the signed 32-bit range raises ValueError,
mirroring that the binary fields are exactly that wide.
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


def getter_a(outer, out):
    """Getter 0x5eeb250: *out = sign_extend32([sub30 + 0xb30])."""
    member = outer["field788"]
    out[0] = _signed32(member["field30"]["fieldb30"])
    return 1


def getter_b(outer, out):
    """Getter 0x5eeb270: *out = [sub30 + 0x1008]."""
    member = outer["field788"]
    out[0] = _u64(member["field30"]["field1008"])
    return 1


def getter_c(outer, out):
    """Getter 0x5eeb2f0: *out = [sub8e8 + 0xcd0]."""
    member = outer["field788"]
    out[0] = _u64(member["field8e8"]["fieldcd0"])
    return 1


def getter_d(outer, out):
    """Getter 0x5eeb320: *out = [sub8e8 + 0xa70]."""
    member = outer["field788"]
    out[0] = _u64(member["field8e8"]["fielda70"])
    return 1


def getter_e(outer, out):
    """Getter 0x5eeb350: *out = [sub8e8 + 0xa78]."""
    member = outer["field788"]
    out[0] = _u64(member["field8e8"]["fielda78"])
    return 1


def getter_f(outer, out):
    """Getter 0x5eeb380: *out = [member + 0x928]."""
    member = outer["field788"]
    out[0] = _u64(member["field928"])
    return 1
