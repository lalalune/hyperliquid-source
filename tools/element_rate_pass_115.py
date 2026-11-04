"""Node #115 element-rate pass.

Maps RE-001 window 0x5f6b660 (181 bytes) from the digest-verified
node #115 binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Object layout (all offsets are from the object base; values are
unsigned 64-bit unless noted):

  +0xfa0  divisor: when zero, the rate is zero and no division runs.
  +0xf98  first dividend part.
  +0xf90  second part, added to +0xf98 for the final divisor only.
  +0xf88  multiplier.
  +0x10   signed 32-bit group count.
  +0xa98  group array base: 24-byte entries (begin, end, third qword
         never read); each group holds element pointers 8 bytes apart.

An element carries the qwords read at element+0x10 (base), +0x80
(threshold), +0x88 (high), +0xa0 (low), +0xa8 (addend), and the
qword at element+0x78, which is both the already-processed flag and
the output field.

Rate rule, stated literally (note the dividend of the first division
carefully: it is +0xf98 alone, NOT +0xf98 + +0xf90):

  if +0xfa0 == 0: rate = 0
  else: rate = (((+0xf98 // +0xfa0) * +0xf88) mod 2**64)
             // ((+0xf98 + +0xf90) mod 2**64)

  The additions and the multiplication wrap at 64 bits; both
  divisions are unsigned. When +0xfa0 != 0 and (+0xf98 + +0xf90) wraps
  to zero, the second division traps in the native code; the model
  raises ElementRatePassError for that input instead.

  The rate is computed BEFORE the group-count check, exactly as the
  native code orders the two blocks, so the trap above fires even
  when the group count is non-positive.

Pass rule, stated literally:

  If the signed 32-bit group count is <= 0, return without touching
  any element. Otherwise walk groups 0..count-1 in order; an empty
  group (begin == end) contributes nothing. For each element pointer
  in a group, in order: if the element's +0x78 field is nonzero, skip
  the element entirely. Otherwise:

    delta2 = (2 * ((element+0x88 - element+0xa0) mod 2**64)) mod 2**64
    if delta2 < element+0x80 (unsigned): result = element+0x10
    else: result = element+0x10
                   + (2 * (((delta2 - element+0x80) * rate) mod 2**64))
                     mod 2**64
    element+0x78 = (result + element+0xa8) mod 2**64

  All additions, subtractions and multiplications wrap at 64 bits.
  The pass is idempotent: a second run recomputes the same +0x78
  values from inputs the first run never changes (except for an
  element whose computed +0x78 is exactly zero, which the second run
  processes again and sets to the same zero).

A null element, a missing element field, or fewer supplied groups
than the count are model guard errors, not native behaviors: the
native code reads those locations without a check.
"""

MASK64 = (1 << 64) - 1


class ElementRatePassError(ValueError):
    """Guard error for inputs the native code would read unchecked,
    plus the native divide-by-zero trap on a zero final divisor."""


def _u64(value):
    return value & MASK64


def _signed32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def compute_rate(f88, f90, f98, fa0):
    """The rate from the four object fields, in native order."""
    f88, f90, f98, fa0 = _u64(f88), _u64(f90), _u64(f98), _u64(fa0)
    if fa0 == 0:
        return 0
    total = (f98 + f90) & MASK64
    if total == 0:
        raise ElementRatePassError(
            "native divide-by-zero: +0xf98 + +0xf90 wraps to zero")
    return (((f98 // fa0) * f88) & MASK64) // total


def make_element(e10=0, e80=0, e88=0, ea0=0, ea8=0, e78=0):
    """Build an element dict in the layout above."""
    return {
        "e10": _u64(e10),
        "e80": _u64(e80),
        "e88": _u64(e88),
        "ea0": _u64(ea0),
        "ea8": _u64(ea8),
        "e78": _u64(e78),
    }


def make_obj(f88=0, f90=0, f98=0, fa0=0, count=0, groups=None):
    """Build an object dict in the layout above."""
    return {
        "f88": _u64(f88),
        "f90": _u64(f90),
        "f98": _u64(f98),
        "fa0": _u64(fa0),
        "count": count,
        "groups": list(groups) if groups is not None else [],
    }


def _element_value(element, field):
    if element is None or field not in element:
        raise ElementRatePassError("missing element field: %s" % field)
    return _u64(element[field])


def apply_element_rate_pass(obj):
    """Run the pass over obj's groups in place; return the rate."""
    for field in ("f88", "f90", "f98", "fa0", "count", "groups"):
        if field not in obj:
            raise ElementRatePassError("missing object field: %s" % field)
    # Native order: the rate is computed before the count check.
    rate = compute_rate(obj["f88"], obj["f90"], obj["f98"], obj["fa0"])
    count = _signed32(obj["count"])
    if count <= 0:
        return rate
    groups = obj["groups"]
    if len(groups) < count:
        raise ElementRatePassError(
            "fewer supplied groups (%d) than count (%d)"
            % (len(groups), count))
    for group in groups[:count]:
        for element in group:
            if _element_value(element, "e78") != 0:
                continue
            e10 = _element_value(element, "e10")
            e80 = _element_value(element, "e80")
            e88 = _element_value(element, "e88")
            ea0 = _element_value(element, "ea0")
            ea8 = _element_value(element, "ea8")
            delta2 = (2 * ((e88 - ea0) & MASK64)) & MASK64
            if delta2 < e80:
                result = e10
            else:
                scaled = ((delta2 - e80) * rate) & MASK64
                result = (e10 + (2 * scaled)) & MASK64
            element["e78"] = (result + ea8) & MASK64
    return rate
