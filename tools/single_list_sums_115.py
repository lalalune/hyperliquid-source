"""Node #115 single-list field sums (RE-001).

Models two whole 48-byte windows plus their three whole getters, all
extracted from the digest-verified node #115 binary (see
research/work-items/RE-001-single-list-sums-115/).

List layout, identical in both windows (read literally from the
excerpts):
  * the header's first-node pointer lives at header + 0x00;
  * each node links to the next node at node + 0x00;
  * each node's payload pointer lives at node + 0x10;
  * the walk ends when a next pointer equals the header itself;
  * an empty list (first node == header) sums to 0.
  * window A (0x5f13060) adds the qword at payload + 0xa70;
  * window B (0x5f13100) adds the qword at payload + 0xa78.
All addition is 64-bit wrapping arithmetic, as in the binary.

The getters take an outer object whose + 0x788 slot holds an inner
object; the inner object's + 0x8f8 slot holds the list header and its
+ 0x8e8 slot holds a record. Getter A (0x5eeb510) stores window A's
sum, getter B (0x5eeb540) stores window B's sum, and both return 1.

The composite getter (0x5eeb570) stores one value and returns 1:
  base = record + 0xa70 + A(list) + G(inner + 0x30 + 0x40)
  doubled = 2 * (B(list) + record + 0xa78)   (64-bit wrapping)
  result = base - doubled  if doubled < base (unsigned, wrapped
  values compared) else 0.
G is the callee at 0x5f6ad70, modelled by contract only: it is called
exactly once, with the single argument above, and its return value is
added into the base. Its internals were not read, so no claim is made
about them. A caller supplies it (a test stub, for example).

A chain that never reaches the header never terminates in the binary;
the model raises ValueError instead of looping forever. That bound is
a model safety guard, not binary behaviour.
"""

MASK64 = (1 << 64) - 1


class Node:
    """One intrusive-list node: ``next`` node and a payload mapping."""

    def __init__(self, payload, nxt=None):
        self.payload = payload
        self.next = nxt


class Header:
    """A list header whose first-node pointer is the list itself."""

    def __init__(self):
        self.first = self  # empty list: first node == header


def link(header, nodes):
    """Chain ``nodes`` after ``header`` in order; terminates at header."""
    prev = header
    for node in nodes:
        if prev is header:
            header.first = node
        else:
            prev.next = node
        prev = node
    prev.next = header
    return header


def _sum_field(header, field):
    total = 0
    node = header.first
    seen = set()
    while node is not header:
        if id(node) in seen:
            raise ValueError("non-terminating chain: node revisited")
        seen.add(id(node))
        total = (total + node.payload[field]) & MASK64
        node = node.next
    return total


def sum_a70(header):
    """Window A (0x5f13060): sum of payload + 0xa70 over the list."""
    return _sum_field(header, "a70")


def sum_a78(header):
    """Window B (0x5f13100): sum of payload + 0xa78 over the list."""
    return _sum_field(header, "a78")


class Inner:
    """Inner object: + 0x8f8 list header, + 0x8e8 record, + 0x30 base."""

    def __init__(self, list_header, record, field30):
        self.list_header = list_header
        self.record = record  # mapping with "a70" and "a78" qwords
        self.field30 = field30


class Outer:
    """Outer object: + 0x788 slot holds the inner object."""

    def __init__(self, inner):
        self.inner = inner


def getter_a(outer):
    """Getter 0x5eeb510: (window A sum, 1)."""
    return sum_a70(outer.inner.list_header), 1


def getter_b(outer):
    """Getter 0x5eeb540: (window B sum, 1)."""
    return sum_a78(outer.inner.list_header), 1


def composite(outer, g_func):
    """Composite getter 0x5eeb570: (clamped remainder, 1).

    ``g_func`` stands in for the 0x5f6ad70 callee by contract.
    """
    inner = outer.inner
    base = (inner.record["a70"] + sum_a70(inner.list_header)
            + g_func((inner.field30 + 0x40) & MASK64)) & MASK64
    doubled = (2 * ((sum_a78(inner.list_header)
                     + inner.record["a78"]) & MASK64)) & MASK64
    if doubled < base:
        result = (base - doubled) & MASK64
    else:
        result = 0
    return result, 1
