"""Python model of node #115's distinct-key sum 0x5f90da0.

Implements the semantics pinned by
research/work-items/RE-001-distinct-key-sum-115. The walk is reached
only through getter 0x5eeb3a0 and stub 0x5d8c9c0 (mapped by #2298) and
computes, over the +0x1028 chain starting at head, the sum of
``[F + 0x10] + 62`` for the first occurrence of each key, where each
16-byte entry in a node's [+0xb18, +0xb20) range holds an object
pointer E, F = [E], and the key is [F]. A key seen in any earlier
entry of any earlier node contributes nothing when it recurs.

State shapes (all plain dicts, no binary layout):

- ``nodes`` maps a node id to ``{"next": node_id, "entries": [entry]}``,
  mirroring the qword at node + 0x1028 and the entry range at node +
  0xb18 / node + 0xb20. The head itself is a node in this map; the
  walk starts at ``nodes[head]["next"]`` and stops when it returns to
  head, so a self-loop head (``next`` == head) yields 0.
- An entry is ``{"obj": obj_id}`` mirroring the pointer at entry + 0x0.
  An entry may also carry an ``"ignored"`` value mirroring the second
  qword at entry + 0x8; the model never reads it, matching the binary.
- ``objects`` maps an object id to ``{"key": int, "field10": int}``,
  mirroring the qwords at F + 0x0 (the key) and F + 0x10 (the summed
  field). The leaf 0x5dd3570 returns ``field10 + 62``.

Model-side notes (not binary behavior, stated explicitly): the binary
has no null checks and would fault on a dangling pointer; a missing
node, entry object, or field raises KeyError, mirroring a fault. A
key or field value outside the unsigned 64-bit range raises
ValueError, mirroring that the binary fields are exactly that wide.
A chain that never returns to head loops forever in the binary; the
model raises ValueError instead, as a model-only guard. The local
set's insert helper 0x5f90bb0 is modelled only as insert-if-absent:
the walk calls it only after its own membership test failed, so its
rehash internals cannot change the total.
"""

MASK64 = (1 << 64) - 1
LEAF_ADDEND = 62


def _u64(value):
    if not 0 <= value <= MASK64:
        raise ValueError("field value %r is outside unsigned 64-bit range" % (value,))
    return value


def value_of(obj):
    """Value leaf 0x5dd3570: [F + 0x10] + 62, 64-bit wrapping."""
    return (_u64(obj["field10"]) + LEAF_ADDEND) & MASK64


def distinct_key_sum(head, nodes, objects):
    """Walk 0x5f90da0: distinct-key sum over the +0x1028 chain.

    ``head`` is a node id in ``nodes``. Returns the total, or 0 for a
    self-loop head.
    """
    seen = set()
    total = 0
    node = nodes[head]["next"]
    visited = set()
    while node != head:
        if node in visited:
            raise ValueError("chain does not return to head")
        visited.add(node)
        for entry in nodes[node]["entries"]:
            obj = objects[entry["obj"]]
            key = _u64(obj["key"])
            if key in seen:
                continue
            seen.add(key)
            total = (total + value_of(obj)) & MASK64
        node = nodes[node]["next"]
    return total
