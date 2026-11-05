"""Model of node #115 routine 0x5a2f760: one step of an async
value whose pending arm converts an f64 number of seconds into a
Duration-shaped value and asks a predicate about it.

The object the routine operates on (rdi) is laid out as:
  +0x00  f64 seconds input
  +0x08  a 0x70-byte value slot (built on the tag-0 arm)
  +0x78  tag byte: 0 = fresh, 1 = completed, 2 = panicking,
         3 = value ready

Behaviour, following the binary instruction by instruction:

* Tag 0: convert the f64 at +0x00 to (secs, nanos) with the exact
  integer algorithm transcribed in convert_f64_seconds (the same
  algorithm whose panic location record names
  library/core/src/time.rs line 962 column 23; negative inputs and
  NaN take the error-kind-0 panic, inputs at or above 2**64 and
  +inf take the error-kind-1 panic, -0.0 converts to (0, 0)). Then
  call the constructor at 0x5cf2150 with (out, secs, nanos,
  &location base/src/lu.rs:75:5), copy the 0x70-byte value into
  +0x08..+0x78, and continue at the predicate step.
* Tag 3: enter the predicate step directly; nothing is converted
  or constructed.
* Predicate step: call 0x5cf2d30 with (obj+0x08, second argument).
  - True: store tag 3 and return the predicate's byte (nonzero).
  - False: decrement the counter behind the pointer at obj+0x10
    (lock decq); only if it reaches zero, call the destructor the
    value's first byte selects (byte 0 -> 0x5ce86d0, nonzero ->
    0x5ce8da0, both with rdi = obj+0x10). Then call the release
    routine 0x5a52490 on obj+0x18, store tag 1 and return 0.
* Tag 1: call the non-returning completion guard 0x1681e60 with
  the static record at 0x64b81c0 (base/src/lu.rs:74:57); it panics
  with "`async fn` resumed after completion".
* Tag 2: call the non-returning panicking guard 0x1681e80 with the
  same record; it panics with "`async fn` resumed after
  panicking". (The completion-guard call follows in the byte
  stream and is unreachable when the first guard does not return.)
* Unwind pads write tag 2 before resuming; one pad first drops the
  value at obj+0x08 through 0x5a423a0, another first releases
  obj+0x18 through 0x5a52490.

Callee bodies (0x5cf2150, 0x5cf2d30, 0x5ce86d0, 0x5ce8da0,
0x5a52490, 0x5a423a0, 0x1680cab) are not modelled; the step model
records their invocations, in order, as effect tuples so tests can
pin the sequence. The model raises on inputs the binary cannot
express (non-integer or out-of-range bit patterns, tags outside
0..3 for the step entry); those guards are model safety
properties, not binary claims. Landing-pad to call-site assignment
is not modelled: the LSDA is not decoded, so only the pads'
literal effects (tag poisoned to 2, plus the two drop calls) are
recorded, in unwind_poisons_tag and the module notes above.
"""

import math
import struct

_MASK64 = (1 << 64) - 1
_NANOS_PER_SEC = 1_000_000_000

CONSTRUCTOR = 0x5CF2150
PREDICATE = 0x5CF2D30
DESTRUCTOR_FOR_FLAG_ZERO = 0x5CE86D0
DESTRUCTOR_FOR_FLAG_NONZERO = 0x5CE8DA0
RELEASE = 0x5A52490

CONVERSION_MESSAGES = {
    0: "cannot convert float seconds to Duration: value is negative",
    1: "cannot convert float seconds to Duration: value is either too big or NaN",
}

GUARD_MESSAGES = {
    1: "`async fn` resumed after completion",
    2: "`async fn` resumed after panicking",
}


class ConversionPanic(Exception):
    """The conversion arm's non-returning panic; kind is the
    error-kind byte (0 = negative/NaN arm, 1 = too-big arm) whose
    Display text is CONVERSION_MESSAGES[kind]."""

    def __init__(self, kind):
        super().__init__(CONVERSION_MESSAGES[kind])
        self.kind = kind
        self.message = CONVERSION_MESSAGES[kind]


class GuardPanic(Exception):
    """A resume guard's non-returning panic for tags 1 and 2."""

    def __init__(self, tag):
        super().__init__(GUARD_MESSAGES[tag])
        self.tag = tag
        self.message = GUARD_MESSAGES[tag]


def _check_bits(bits):
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise TypeError("bits must be an int")
    if bits < 0 or bits > _MASK64:
        raise ValueError("bits is not a 64-bit pattern")


def convert_f64_seconds(bits):
    """Convert the f64 whose IEEE-754 bits are ``bits`` to a
    (secs, nanos) pair, transcribing the binary's integer
    algorithm band by band. Raises ConversionPanic for the two
    panic arms."""
    _check_bits(bits)
    value = struct.unpack("<d", struct.pack("<Q", bits))[0]
    # ucomisd with 0.0: the ja is taken when 0.0 > value or the
    # comparison is unordered (NaN). -0.0 does not take it.
    if math.isnan(value) or 0.0 > value:
        raise ConversionPanic(0)
    exponent = (bits >> 52) & 0x7FF
    if exponent < 0x3E0:
        # value < 2**-31 (including +0.0, -0.0 and subnormals)
        return (0, 0)
    mantissa = (bits & 0xFFFFFFFFFFFFF) + 0xFFFFFFFFFFFFF + 1
    if exponent >= 0x43F:
        # value >= 2**64, including +inf
        raise ConversionPanic(1)
    if exponent >= 0x433:
        # 2**52 <= value < 2**64: already an integer
        shift = ((exponent & 0xFF) + 0xCD) & 0xFF
        return ((mantissa << (shift & 63)) & _MASK64, 0)
    if exponent >= 0x3FF:
        # 1 <= value < 2**52
        exponent_delta = (exponent - 0x3FF) & 0xFFFFFFFF
        low_byte = (0x33 - (exponent & 0xFF)) & 0xFF
        secs = mantissa >> (low_byte & 63)
        rax = (bits << (exponent_delta & 63)) & _MASK64
        rax &= 0xFFFFFFFFFFFFF
        product = rax * _NANOS_PER_SEC
        rax_lo = product & _MASK64
        high = product >> 64
        nanos = ((rax_lo >> 52)
                 | (((high & 0xFFFFFFFF) << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF
        round_bit = 0
        if (rax_lo >> 51) & 1:
            masked = rax_lo & 0x000FFFFFFFFFFE00
            flag = 1 if masked != 0x8000000000000 else 0
            flag |= nanos & 0xFF
            round_bit = flag & 1
        nanos = (nanos + round_bit) & 0xFFFFFFFF
        carry = 0
        if nanos == _NANOS_PER_SEC:
            carry, nanos = 1, 0
        return (secs + carry, nanos)
    # 2**-31 <= value < 1
    cl = ((exponent & 0xFF) + 0x2D) & 0xFF
    count = cl & 63
    high = (mantissa >> (64 - count)) if count else 0
    low = (mantissa << count) & _MASK64
    if cl & 0x40:
        high, low = low, 0
    product = low * _NANOS_PER_SEC
    rax_lo = product & _MASK64
    combined = ((product >> 64) + ((high * _NANOS_PER_SEC) & _MASK64)) & _MASK64
    nanos_candidate = combined >> 32
    round_bit = 0
    if combined & 0x80000000:
        masked = rax_lo & 0xFFFFFFFFFFFFFE00
        merged = ((0x80000000 ^ (combined & 0xFFFFFFFF)) | masked) & _MASK64
        flag = 1 if merged != 0 else 0
        flag |= nanos_candidate & 0xFF
        round_bit = flag & 1
    nanos = ((nanos_candidate & 0xFFFFFFFF) + round_bit) & 0xFFFFFFFF
    secs = 0
    if nanos == _NANOS_PER_SEC:
        secs, nanos = 1, 0
    return (secs, nanos)


class StepObject:
    """The modelled object: tag byte, the f64 input bits, and the
    constructed value's flag byte (the byte at obj+0x08 once a
    value exists)."""

    def __init__(self, tag, f64_bits=0, value_flag=0):
        if tag not in (0, 1, 2, 3):
            raise ValueError("tag outside the modelled 0..3 range")
        _check_bits(f64_bits)
        if value_flag not in (0, 1):
            raise ValueError("value_flag must be 0 or 1")
        self.tag = tag
        self.f64_bits = f64_bits
        self.value_flag = value_flag


def step(obj, predicate_result, counter_reaches_zero=True,
         constructed_flag=0):
    """Run one step of the routine over ``obj``.

    ``predicate_result`` is the boolean the predicate callee
    returns; ``counter_reaches_zero`` says whether the lock decq
    on the false path reaches zero; ``constructed_flag`` is the
    flag byte of the value the constructor builds on the tag-0
    arm. Returns (returned, effects): returned is True/False for
    the predicate's byte, effects is the ordered list of callee
    effect tuples. Raises ConversionPanic or GuardPanic for the
    non-returning arms; on a raise the object's tag is unchanged.
    """
    if constructed_flag not in (0, 1):
        raise ValueError("constructed_flag must be 0 or 1")
    if obj.tag == 1:
        raise GuardPanic(1)
    if obj.tag == 2:
        raise GuardPanic(2)
    effects = []
    if obj.tag == 0:
        secs, nanos = convert_f64_seconds(obj.f64_bits)
        effects.append(("construct", CONSTRUCTOR, secs, nanos))
        obj.value_flag = constructed_flag
    effects.append(("predicate", PREDICATE))
    if predicate_result:
        obj.tag = 3
        return (True, effects)
    effects.append(("decq",))
    if counter_reaches_zero:
        destructor = (DESTRUCTOR_FOR_FLAG_ZERO if obj.value_flag == 0
                      else DESTRUCTOR_FOR_FLAG_NONZERO)
        effects.append(("destroy", destructor))
    effects.append(("release", RELEASE))
    obj.tag = 1
    return (False, effects)


def unwind_poisons_tag(obj):
    """The landing pads' common literal effect: the tag byte is
    overwritten with 2 before the unwind resumes."""
    obj.tag = 2
    return obj.tag
