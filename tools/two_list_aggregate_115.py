"""Model of node #115 two-list aggregate 0x5f13130 and its consumers.

The window sums, over every node of two lists hanging off its
argument object, three per-payload terms: the virtual slot-0x78
results of the subobjects at payload + 0xa50 and payload + 0xa58
(taken as inputs, by contract) and the direct qword at
payload + 0xa00. When the second list is non-empty it subtracts
the same three terms of the distinguished object at object + 0x20.
All arithmetic wraps at 64 bits, as in the window.

Consumers modelled thinly from their own windows:
- threshold check 0x5f13240 (call site 0x5f1327b);
- cache refresh 0x5f13450 (call site 0x5f1345c).
"""

MASK = (1 << 64) - 1


class Payload:
    """One list node's payload, as the window reads it."""

    def __init__(self, slot_a50, slot_a58, direct):
        self.slot_a50 = slot_a50
        self.slot_a58 = slot_a58
        self.direct = direct


def element_terms(payload):
    """The three terms of one payload, in the window's order."""
    return (payload.slot_a50 + payload.slot_a58 + payload.direct) & MASK


def aggregate(list1, list2, distinguished=None):
    """The 0x5f13130 total.

    list1/list2 are ordered lists of Payload. distinguished is the
    payload of the object at object + 0x20. When list2 is non-empty
    and distinguished is None, the model raises: the window has no
    null guard there and would fault on the load instead.
    """
    total = 0
    for payload in list1:
        total = (total + element_terms(payload)) & MASK
    for payload in list2:
        total = (total + element_terms(payload)) & MASK
    if list2:
        if distinguished is None:
            raise ValueError(
                "distinguished object required when the second "
                "list is non-empty (the window has no null guard)")
        terms = element_terms(distinguished)
        total = (total - terms) & MASK
    return total


def threshold_check(limit38, seed30, field10, field28, base, total):
    """The 0x5f13240 threshold check on an aggregate total.

    limit38 is the signed 64-bit field at + 0x38, seed30 the
    sign-extended dword at + 0x30, field10/field28 the qwords at
    + 0x10/+ 0x28, base the caller's second argument, total the
    aggregate of the same object. Comparisons are unsigned 64-bit,
    as the window's setae/setb implement them; the limit38 > 0
    test itself is signed.
    """
    if limit38 > 0:
        return ((base + total) & MASK) >= (limit38 & MASK)
    if seed30 <= 0:
        return False
    return ((field10 + field28) & MASK) > (seed30 & MASK)


def refresh(total, list2_nonempty):
    """The 0x5f13450 cache refresh: store the total and the flag."""
    return {"cached_total": total & MASK,
            "list2_nonempty": bool(list2_nonempty)}
