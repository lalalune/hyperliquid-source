"""Python model of node #115's aggregate-sum getter 0x5eeb650, its
forwarding stub 0x5d8c9d0, and the aggregate sum 0x5f6acb0.

Implements the semantics pinned by
research/work-items/RE-001-aggregate-sum-getter-115. The getter takes
(outer, out): it loads the member at [outer + 0x788], calls the stub
with it, stores the stub's return to *out, and returns 1
unconditionally. The stub loads the aggregate object at
[member + 0x30] and tail-jumps to the aggregate, so the aggregate's
return passes through unchanged. The aggregate reads a signed
32-bit group count at [obj + 0x50]; count <= 0 returns 0 at once.
Otherwise it walks the first count 24-byte groups at [obj + 0xad8]
and adds, for every pointer in each group's [begin, end) range, the
qword at [pointer + 0x10] to a 64-bit wrapping total.

State shapes (all plain dicts, no binary layout):

- An aggregate object is ``{"count": int, "groups": [[...], ...]}``
  where each group is a list of the + 0x10 values of its elements,
  in range order. Valid inputs have len(groups) == count when
  count > 0; the model iterates the first count groups.
- An outer object is ``{"field788": member}`` mirroring the qword
  at outer + 0x788, and a member object is ``{"field30": obj}``
  mirroring the qword at member + 0x30. ``out`` is modelled as a
  one-element list, mirroring the rsi pointer the getter stores to.

Model-side notes (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer;
a missing field raises KeyError, mirroring a fault. The binary
processes element pairs with SIMD paddq and handles a lone final
element separately; the observable total is the plain sum, which
the model computes directly. The total wraps at 64 bits, as the
binary's paddq/addq do; tests stay inside the range where wrapping
is invisible except for one explicit wrap test.
"""

MASK64 = (1 << 64) - 1


def aggregate_sum(obj):
    """Aggregate sum 0x5f6acb0: sum of + 0x10 fields over groups.

    Returns 0 when the signed 32-bit count at + 0x50 is <= 0.
    Otherwise sums every element's value across the first count
    groups, wrapping at 64 bits.
    """
    count = obj["count"]
    if count <= 0:
        return 0
    total = 0
    for group in obj["groups"][:count]:
        for value in group:
            total = (total + value) & MASK64
    return total


def forwarding_stub(member):
    """Forwarding stub 0x5d8c9d0: tail-jump to the aggregate.

    Loads the aggregate object at [member + 0x30] and returns the
    aggregate's result unchanged.
    """
    return aggregate_sum(member["field30"])


def aggregate_sum_getter(outer, out):
    """Getter 0x5eeb650: *out = aggregate sum, return 1.

    Loads the member at [outer + 0x788], forwards it through the
    stub to the aggregate, stores the result to out[0], and returns
    1 unconditionally. There is no null check anywhere in this
    behavior; a missing field raises KeyError, mirroring a fault.
    """
    member = outer["field788"]
    out[0] = forwarding_stub(member)
    return 1
