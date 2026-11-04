"""Python model of node #115's rdx-arg getters 0x5eeb6c0/0x5eeb6e0/
0x5eeb700/0x5eeb720 and their leaves 0x5e4b550/0x5e4b560/0x5fc9610.

Implements the semantics pinned by
research/work-items/RE-001-rdx-getters-115. All four getters share
one shape: arguments (outer, out, obj); the outer object is IGNORED
by every getter; each stores one qword to ``out`` (modelled as a
one-element list) and returns 1 unconditionally.

State shapes (all plain dicts, no binary layout):

- A leaf550 object is ``{"slot68": {"field_e0": value}}``: ``slot68``
  mirrors the qword at obj + 0x68, ``field_e0`` the qword at
  slot + 0xe0.
- A leaf560 object is ``{"head_first": node_or_None}``: ``None``
  stands for the empty list (first node equal to the head itself),
  otherwise ``node`` is ``{"payload": value}`` mirroring [first +
  0x10]. The refresh call is modelled as a caller-supplied callable
  receiving the object; the binary passes obj + 0x700 and ignores
  the return, which the README states explicitly.
- A getter E object is ``{"count": signed_int, "ptr": value}``:
  ``count`` mirrors the signed 32-bit value at obj + 0x1104,
  ``ptr`` the qword at obj + 0x1128.
- A getter F value is a signed 32-bit int mirroring [obj + 0x1100].

Model-side guards (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer.
``leaf560`` returns MASK64 for the empty list, matching the binary's
0xffffffffffffffff in rax (signed -1).
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def _to_signed32(value):
    value &= MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def leaf550(obj):
    """Leaf 0x5e4b550: return [[obj + 0x68] + 0xe0], no null check."""
    return obj["slot68"]["field_e0"]


def leaf560(obj, refresh):
    """Leaf 0x5e4b560.

    Calls ``refresh`` first (the binary's 0x60d5390 on obj + 0x700,
    by contract, return ignored), then returns MASK64 (signed -1)
    for the empty list or the first node's payload otherwise.
    """
    refresh(obj)
    first = obj["head_first"]
    if first is None:
        return MASK64
    return first["payload"]


def leaf610_raw(value32):
    """Leaf 0x5fc9610 raw return, quirk included.

    The leaf loads the signed 32-bit value, tests it, and sets only
    the low byte of eax: the raw return keeps the loaded value's
    upper 24 bits and forces the low byte to 1 (positive) or 0
    (zero or negative). It is NOT a clean 0/1.
    """
    value = _to_signed32(value32)
    return (value & 0xFFFFFF00) | (1 if value > 0 else 0)


def getter_c(outer, out, obj):
    """Getter 0x5eeb6c0: *out = leaf550(obj); return 1. Outer ignored."""
    out[0] = leaf550(obj)
    return 1


def getter_d(outer, out, obj, refresh):
    """Getter 0x5eeb6e0: *out = leaf560(obj); return 1. Outer ignored."""
    out[0] = leaf560(obj, refresh)
    return 1


def getter_e(outer, out, obj):
    """Getter 0x5eeb700: *out = ptr if count > 0 else 0; return 1."""
    count = _to_signed32(obj["count"])
    out[0] = obj["ptr"] if count > 0 else 0
    return 1


def getter_f(outer, out, value32):
    """Getter 0x5eeb720: *out = movzbl(leaf610(obj + 0x1100)).

    The movzbl keeps only the leaf's low byte, so the stored value
    is exactly 1 iff the signed 32-bit value is positive, else 0.
    Outer ignored; ``value32`` mirrors [obj + 0x1100].
    """
    out[0] = leaf610_raw(value32) & 0xFF
    return 1
