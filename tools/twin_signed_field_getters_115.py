"""Python model of node #115's twin signed-field getters 0x5eeb400/0x5eeb430
and their leaves 0x5f12a10/0x5f12a20.

Implements the semantics pinned by
research/work-items/RE-001-twin-signed-field-getters-115. Each getter
takes (outer, out): it loads the member at [outer + 0x788], forms
arg = member + 0x8f0, calls its leaf with that arg, sign-extends the
leaf's 32-bit return (cltq), stores it to *out, and returns 1
unconditionally. Leaf A returns the signed 32-bit value at
[inner + 0x10] and leaf B the signed 32-bit value at [inner + 0x28],
where inner = [arg + 0x8] in both cases. Neither getter nor leaf has
a null check anywhere.

State shapes (all plain dicts, no binary layout):

- An outer object is ``{"field788": member}`` mirroring the qword
  at outer + 0x788. A member object is ``{"field8f0": sub}``
  mirroring the sub-object at member + 0x8f0. A sub-object is
  ``{"field8": inner}`` mirroring the qword at arg + 0x8, and an
  inner object is ``{"field10": int, "field28": int}`` mirroring
  the signed 32-bit fields at inner + 0x10 and inner + 0x28.
  ``out`` is modelled as a one-element list, mirroring the rsi
  pointer the getter stores to.

Model-side notes (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer;
a missing field raises KeyError, mirroring a fault. The leaf's
32-bit return is modelled as a Python int already sign-extended
from 32 bits, which is exactly what the getter's cltq observes;
a leaf value outside the signed 32-bit range raises ValueError,
mirroring that the binary field is 32 bits wide.
"""

MASK64 = (1 << 64) - 1
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1


def _signed32(value):
    if not INT32_MIN <= value <= INT32_MAX:
        raise ValueError("field value %r is outside signed 32-bit range" % (value,))
    return value


def leaf_a(arg):
    """Leaf 0x5f12a10: return signed32([inner + 0x10])."""
    inner = arg["field8"]
    return _signed32(inner["field10"])


def leaf_b(arg):
    """Leaf 0x5f12a20: return signed32([inner + 0x28])."""
    inner = arg["field8"]
    return _signed32(inner["field28"])


def getter_a(outer, out):
    """Getter 0x5eeb400: *out = sign_extend(leaf_a(member + 0x8f0))."""
    member = outer["field788"]
    out[0] = leaf_a(member["field8f0"])
    return 1


def getter_b(outer, out):
    """Getter 0x5eeb430: *out = sign_extend(leaf_b(member + 0x8f0))."""
    member = outer["field788"]
    out[0] = leaf_b(member["field8f0"])
    return 1
