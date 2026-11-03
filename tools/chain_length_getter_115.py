"""Python model of node #115's chain-length getter 0x5eeb610, its
forwarding stub 0x5d8c9a0, and the chain-length counter 0x5f70180.

Implements the semantics pinned by
research/work-items/RE-001-chain-length-getter-115. The getter takes
(outer, out): it loads the member at [outer + 0x788], calls the stub
with it, stores the stub's return to *out, and returns 1
unconditionally. The stub loads the chain head at [member + 0x28]
and tail-jumps to the counter, so the counter's return passes
through unchanged. The counter walks the +0x1028 links from the
head until the walk returns to the head, counting the non-head
nodes in the cycle.

State shapes (all plain dicts, no binary layout):

- A chain is a dict mapping a node id to the id of its successor,
  mirroring [node + 0x1028]. The head's own entry is the first
  link the counter reads.
- An outer object is ``{"field788": member}`` mirroring the qword
  at outer + 0x788, and a member object is ``{"field28": head}``
  mirroring the qword at member + 0x28. ``out`` is modelled as a
  one-element list, mirroring the rsi pointer the getter stores to.

Model-side guards (not binary behavior, stated explicitly): the
binary has no null checks and would fault on a dangling pointer,
and a chain that never returns to its head would loop forever;
the model raises KeyError for a missing link (mirroring a fault
on an out-of-range read) and ValueError for a cycle that never
returns to head (mirroring the unbounded loop). Counts use plain
Python integers (the binary wraps at 64 bits; tests stay inside
the range where wrapping is invisible).
"""


def chain_length(head, chain):
    """Chain-length counter 0x5f70180: non-head nodes in the cycle.

    Returns 0 when the head points at itself, 1 for a two-node
    cycle, and so on. Raises ValueError when the walk cycles
    without ever returning to head (model-only guard; the binary
    would loop forever), and KeyError for a missing link.
    """
    count = 0
    node = chain[head]
    seen = set()
    while node != head:
        if node in seen:
            raise ValueError("chain never returns to head")
        seen.add(node)
        node = chain[node]
        count += 1
    return count


def forwarding_stub(member, chain):
    """Forwarding stub 0x5d8c9a0: tail-jump to the counter.

    Loads the chain head at [member + 0x28] and returns the
    counter's result unchanged.
    """
    return chain_length(member["field28"], chain)


def chain_length_getter(outer, out, chain):
    """Getter 0x5eeb610: *out = chain length, return 1.

    Loads the member at [outer + 0x788], forwards it through the
    stub to the counter, stores the result to out[0], and returns
    1 unconditionally. There is no null check anywhere in this
    behavior; a missing field raises KeyError, mirroring a fault.
    """
    member = outer["field788"]
    out[0] = forwarding_stub(member, chain)
    return 1
