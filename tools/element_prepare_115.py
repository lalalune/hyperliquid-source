"""Python model of node #115's element-prepare function 0x5f13310.

Implements the semantics pinned by
research/work-items/RE-001-element-prepare-115: the guard
acquire/release pairing (by contract), the count formula, the
two-array element selection, the per-element zero store at + 0xa88
and prepare callback standing in for 0x5f54ee0 (by contract only),
the holder counter at + 0x10, and the holder ready byte at + 0x00.

A collection is a dict {"field_0x00": int, "first": [element, ...],
"second": [element, ...]}; each element is a dict that the model
annotates with "zeroed_0xa88" and passes (as element + 0xa98, i.e.
the element itself here) to the prepare callback. A holder is a dict
{"counter": int, "ready": 0_or_1}; the guard log records
("acquire", 9) and ("release",) in order.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def _to_signed64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def count_total(collection):
    """The binary's count formula, exactly as written."""
    span = (len(collection["second"]) * 8) & MASK64
    # The binary subtracts end - begin in 64-bit wrapping arithmetic,
    # then arithmetic-shifts right by 3, then adds field + 0x00.
    shifted = _to_signed64(span) >> 3
    total = (_to_signed64(collection["field_0x00"]) + shifted) & MASK64
    return _to_signed64(total)


def element_prepare(holder, collection, prepare):
    """The 0x5f13310 window. Returns the guard log.

    prepare(element) stands in for 0x5f54ee0, called once per element
    with element + 0xa98 after the two zero bytes at element + 0xa88.
    A negative total raises instead of looping forever (see the
    packet README: the binary would not terminate that loop).
    """
    guard_log = [("acquire", 9)]
    total = count_total(collection)
    if total < 0:
        raise ValueError("negative element total never terminates")
    first = collection["first"]
    second = collection["second"]
    for index in range(total):
        if index < 8:
            if index >= len(first):
                raise IndexError("first array index out of range")
            element = first[index]
        else:
            if index - 8 >= len(second):
                raise IndexError("second array index out of range")
            element = second[index - 8]
        element["zeroed_0xa88"] = True
        prepare(element)
        holder["counter"] = (holder["counter"] + 1) & MASK32
        # The binary's 32-bit counter wraps; keep it in 0..2**32-1 and
        # let callers read it as signed only if they need to.
    holder["ready"] = 1
    guard_log.append(("release",))
    return guard_log
