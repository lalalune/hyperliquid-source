"""Python model of node #115's distinct-sum getter 0x5eeb630, its
forwarding stub 0x5d8c9b0, and the distinct-key sum 0x5f91010.

Implements the semantics pinned by
research/work-items/RE-001-distinct-sum-getter-115. The getter takes
(outer, out): it loads the member at [outer + 0x788], calls the stub
with it, stores the stub's return to *out, and returns 1
unconditionally. The stub loads the aggregate object at
[member + 0x28] and tail-jumps to the distinct sum, so the sum's
return passes through unchanged. The distinct sum walks the +0x1028
cycle starting at [obj + 0x1028] and stopping when it returns to obj
(the head object itself is never summed; a self-loop returns 0).
For each cycle node it reads a signed 32-bit group count at
[node + 0x50]; count <= 0 skips that node. Otherwise it walks the
first count 24-byte groups at [node + 0xad8]; for every pointer p in
a group's [begin, end) range it reads the element at *p, takes the
key at [element + 0x08], and, only when that key has not been seen
before, adds the qword at [element + 0x10] to a 64-bit wrapping
total. A duplicate key contributes nothing.

State shapes (all plain dicts, no binary layout):

- A cycle node is ``{"count": int, "groups": [[...], ...]}`` where
  each group is a list of ``(key, value)`` pairs in range order,
  key mirroring [element + 0x08] and value mirroring
  [element + 0x10]. Valid inputs have len(groups) == count when
  count > 0; the model iterates the first count groups.
- A distinct-sum head object is ``{"chain": [node, ...]}`` listing
  the cycle nodes in walk order, head excluded, mirroring the
  +0x1028 links. An empty chain mirrors a self-loop.
- An outer object is ``{"field788": member}`` mirroring the qword
  at outer + 0x788, and a member object is ``{"field28": head}``
  mirroring the qword at member + 0x28. ``out`` is modelled as a
  one-element list, mirroring the rsi pointer the getter stores to.

Model-side notes (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer;
a missing field raises KeyError, mirroring a fault. The binary
tests membership two ways -- a linear scan of stored entries when
its set's +0x18 field is 0, and a bucketed lookup otherwise -- but
both compare the candidate key against a stored +8 field and skip
on equality, so the observable result is the seen-key sum the
model computes directly. The set-node layout and the insert callee
0x5f90bb0 are left by contract (see the packet README); the local
set is destroyed before the function returns, so its bucket
mechanics are unobservable. A chain that never returns to its head
loops forever in the binary; the model takes the cycle as a
finished list, so it cannot express that case. The total wraps at
64 bits, as the binary's addq does; tests stay inside the range
where wrapping is invisible except for one explicit wrap test.
"""

MASK64 = (1 << 64) - 1


def distinct_sum(head):
    """Distinct-key sum 0x5f91010: first-occurrence sum over a cycle.

    Returns 0 for an empty chain (a self-loop). Otherwise sums, for
    each cycle node in order and each of its first count groups,
    the + 0x10 value of every element whose + 0x08 key has not been
    seen before, wrapping at 64 bits.
    """
    seen = set()
    total = 0
    for node in head["chain"]:
        count = node["count"]
        if count <= 0:
            continue
        for group in node["groups"][:count]:
            for key, value in group:
                if key in seen:
                    continue
                seen.add(key)
                total = (total + value) & MASK64
    return total


def forwarding_stub(member):
    """Forwarding stub 0x5d8c9b0: tail-jump to the distinct sum.

    Loads the distinct-sum head object at [member + 0x28] and
    returns the distinct sum's result unchanged.
    """
    return distinct_sum(member["field28"])


def distinct_sum_getter(outer, out):
    """Getter 0x5eeb630: *out = distinct sum, return 1.

    Loads the member at [outer + 0x788], forwards it through the
    stub to the distinct sum, stores the result to out[0], and
    returns 1 unconditionally. There is no null check anywhere in
    this behavior; a missing field raises KeyError, mirroring a
    fault.
    """
    member = outer["field788"]
    out[0] = forwarding_stub(member)
    return 1
