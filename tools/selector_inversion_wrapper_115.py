"""Python model of node #115 selector-inversion wrapper 0x5ebd130 (RE-001).

The whole 136-byte function, end to end: a zero-index fast path plus,
for any nonzero index, one call to the index selector 0x5f6c2a0 whose
result it inverts. The selector is pinned by the RE-001 later-group
predicate item; here it is an oracle callable, exactly the input the
native wrapper consults, and its own dispatch semantics are NOT
re-claimed by this item.

Native shape, stated literally (wrapper window 0x5ebd130..0x5ebd1b8):

  - The wrapper takes (rdi = outer object, rsi = record source,
    edx = index, 32-bit). It presets the return register to 1 and
    tests edx: an index of 0 returns 1 at once, before reading any
    object or record-source field and without calling the selector.
  - Otherwise it reads the qword at outer+0x40 (a struct pointer A),
    then the qword at A+0x30 (a link value); the selector's object
    pointer is that link value plus 0x40 (64-bit wrapping add).
  - It builds two 16-byte records on the stack from the record
    source's fields:
        record 1 = (source+0x20, source+0x28 - 8 wrapping)
        record 2 = (source+0x40, source+0x48 - 8 wrapping)
    and calls the selector as (rdi = selector object, esi = index,
    rdx = record 1 pointer, rcx = record 2 pointer).
  - The wrapper returns the selector's result with its low bit
    flipped (xor $0x1 on the full return register at 0x5ebd19b).
    For the selector's pinned 0/1 contract that is exactly NOT:
    selector 0 -> 1, selector 1 -> 0.

Model inputs:
  index: 32-bit index (edx). The zero test is on the low 32 bits;
      the model accepts a Python int and masks it to 32 bits first,
      then passes the signed 32-bit value to the selector oracle,
      matching the selector's signed comparisons.
  link: the qword value at [outer+0x40]+0x30, or None. Ignored (and
      allowed to be None) on the zero-index path, which reads nothing.
  source: a 4-tuple (f20, f28, f40, f48) of raw qwords from the
      record source, or None. Ignored (and allowed to be None) on
      the zero-index path.
  selector: oracle callable (selector_obj, index_signed32, rec1, rec2)
      returning 0 or 1.

Out of contract, stated honestly: the stack-canary check in the
epilogue is standard hardening, not behaviour, and is not modelled.
Whether the selector or its dispatch mutates the object is not
pinned; the model treats all inputs as stable across one call.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def _wrap64(value):
    return value & MASK64


def _signed32(value):
    value &= MASK32
    return value - (1 << 32) if value >> 31 else value


def selector_inversion_wrapper(index, selector, link=None, source=None):
    """Return the wrapper's result for one call.

    index: 32-bit index (edx). link: the qword at [outer+0x40]+0x30.
    source: (f20, f28, f40, f48) raw qwords. selector: oracle callable
    (selector_obj, index_signed32, rec1, rec2) -> 0 or 1.
    """
    index32 = index & MASK32
    if index32 == 0:
        # Native fast path: return 1 before reading anything else.
        return 1
    if link is None or source is None:
        raise ValueError("nonzero index requires link and source")
    f20, f28, f40, f48 = source
    selector_obj = _wrap64(link + 0x40)
    rec1 = (f20, _wrap64(f28 - 8))
    rec2 = (f40, _wrap64(f48 - 8))
    return selector(selector_obj, _signed32(index32), rec1, rec2) ^ 1
