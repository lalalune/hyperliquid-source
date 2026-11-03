"""Python model of node #115's sibling getters 0x5eeb490/0x5eeb4d0.

Implements the semantics pinned by
research/work-items/RE-001-sibling-getters-115: the header-terminated
list walk at 0x5f133e0 with a per-element callback standing in for
0x5f0e2d0 (by contract only), the field load at 0x5f13420, and the two
sibling getters that add the shared base qword at (inner + 0x8e8) +
0xcd0 to the computed value, store it to *out, and return 1.

A list is a header dict {"first": node_id_or_"HEADER"} plus a nodes
dict mapping each node id to {"payload": value, "next":
node_id_or_"HEADER"}. The walk follows exactly the binary's rule: it
ends when a next pointer equals the header itself, and a chain that
never reaches the header raises instead of looping forever.
"""

MASK64 = (1 << 64) - 1
HEADER = "HEADER"


def field_load(record):
    """The 0x5f13420 window: the qword at argument + 0x18."""
    return record["field_0x18"] & MASK64


def list_sum(header, nodes, per_element):
    """The 0x5f133e0 window. Returns the wrapping 64-bit sum.

    per_element(payload) stands in for 0x5f0e2d0, called once per node
    with the node's payload pointer; its return is added into the sum.
    """
    total = 0
    node = header["first"]
    steps = 0
    while node != HEADER:
        if steps > len(nodes):
            raise ValueError("list walk never reaches its header")
        entry = nodes[node]
        total = (total + per_element(entry["payload"])) & MASK64
        node = entry["next"]
        steps += 1
    return total


def getter_list_sum(base, header, nodes, per_element):
    """The 0x5eeb490 getter: (stored_value, return_value)."""
    return (list_sum(header, nodes, per_element) + (base & MASK64)) & MASK64, 1


def getter_field(base, record):
    """The 0x5eeb4d0 getter: (stored_value, return_value)."""
    return (field_load(record) + (base & MASK64)) & MASK64, 1
