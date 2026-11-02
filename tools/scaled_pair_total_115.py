"""Model of node #115 scaled pair total 0x5f09a50.

The window takes one object (rdi) plus two arguments (rsi, rdx)
that it passes through unchanged to two gated virtual calls. The
object holds two subobjects at + 0xa50 and + 0xa58. For each
subobject the window reads the function pointer at + 0x68 of the
record the subobject points to (the qword at the subobject itself,
then + 0x68 of that record). When that pointer equals the sentinel
address 0x5f04d70 the call is skipped and the subobject contributes
0; otherwise the window calls the pointer with (subobject, rsi,
rdx) and the first call's result starts the running total while
the second call's result is added to it, in 64-bit wrapping
arithmetic.

If the total is 0 the window returns (0, 0) at once. Otherwise it
reads the cap at object + 0xa70; a zero cap also returns (0, 0).
Otherwise the total is clamped down to the cap (clamped =
min(total, cap)), the scale is the unsigned quotient of the field
at object + 0xa68 divided by the cap, and the window returns
(scale * clamped, clamped), the product again in 64-bit wrapping
arithmetic. The remainder of the division is discarded.

The identities of the two virtual functions and the meanings of
the + 0xa68 / + 0xa70 fields are not established by this window
alone and are recorded as unknowns in the work-item README; the
model takes the contributions and the two fields as inputs.
"""

MASK = (1 << 64) - 1

SENTINEL = 0x5F04D70


class Subobject:
    """One of the + 0xa50 / + 0xa58 subobjects.

    slot_fn is the + 0x68 function pointer of the record the
    subobject points to, or None when it equals the sentinel
    0x5f04d70 (the skipped case). contribution is the value the
    virtual call returns for the window's (rsi, rdx) arguments;
    it is unused when slot_fn is None.
    """

    def __init__(self, slot_fn, contribution=0):
        self.slot_fn = slot_fn
        self.contribution = contribution

    @property
    def is_default(self):
        return self.slot_fn is None or self.slot_fn == SENTINEL

    def call(self, _arg1, _arg2):
        if self.is_default:
            return 0
        return self.contribution & MASK


def pair_total(first, second, arg1, arg2):
    """The running total of the two gated calls (0x5f09a50 core)."""
    total = 0
    if not first.is_default:
        total = first.call(arg1, arg2)
    if not second.is_default:
        total = (total + second.call(arg1, arg2)) & MASK
    return total


def scaled_total(first, second, field_a68, field_a70, arg1, arg2):
    """The window's full result: (scaled value, clamped total).

    Returns (0, 0) when the total is 0 or when the cap is 0.
    """
    total = pair_total(first, second, arg1, arg2)
    if total == 0:
        return (0, 0)
    cap = field_a70 & MASK
    if cap == 0:
        return (0, 0)
    clamped = total if total < cap else cap
    scale = (field_a68 & MASK) // cap
    return ((scale * clamped) & MASK, clamped)
