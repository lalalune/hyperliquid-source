#!/usr/bin/env python3
"""Model of node #94 BlockCache chain lookup at 0x514e550 (RE-001).

The window takes one outer object, reads the chain head from
[[outer + 0x788] + 0x620], and searches that polymorphic chain for the
fixed key "BlockCache" (a 10-byte stack string, SSO). Each node carries
a vtable: slot +0x38 is its handler, slot +0x88 is its next-node step.
For each of the first eight nodes, in order:

- if the node's handler differs from the sentinel 0x4f8da10, the
  handler is called with (node, key) and its return value is the
  result;
- otherwise the table helper 0x52f5290 is tried on (node, key): it
  scans the node's 48-byte records from [node + 0x8] to [node + 0x10),
  matching the record key string by length then bytes, and returns the
  matching record's +0x20 first qword, or 0 on a miss;
- on a helper miss the walk steps to the next node via vtable slot
  +0x88; a null next node returns 0.

After eight helper misses the window delegates the remaining walk to
0x514ba10 (the walker bound by RE-001-chain-walk-dispatch-94), which
steps to the next node first and then repeats the same handler/helper
rule without bound. The model is semantic: nodes are plain Python
values, handler results and record payloads are opaque objects, and
the helper's record scan is modelled directly from the walker packet's
established record layout.

Layout (from research/work-items/RE-001-blockcache-chain-lookup-94):
outer +0x788: container pointer; container +0x620: chain head node.
Key bytes: "BlockCache", length 10. Sentinel handler: 0x4f8da10.
Inline trials: 8 (helper call sites 0x514e5c7, 0x514e627, 0x514e67b,
0x514e6b0, 0x514e6ed, 0x514e72a, 0x514e767, 0x514e7a4); delegation site
0x514e7bb. The binary dereferences the head node without a null
check, so a null head is outside the modelled contract and raises.
"""

INLINE_TRIALS = 8
KEY = b"BlockCache"
SENTINEL = 0x4F8DA10


class NullHeadError(ValueError):
    """The head node is null; the binary has no guard for this."""


class ChainNode:
    """One chain node: a handler, a record table, and a next node.

    ``handler`` is None for the sentinel (helper-trial) nodes, or a
    callable taking (node, key) returning an opaque result for
    handler-dispatched nodes. ``records`` is a list of (key, payload)
    pairs scanned by the helper in order. ``next_node`` is the next
    chain node or None.
    """

    def __init__(self, records=(), handler=None, next_node=None):
        self.records = [(bytes(k), p) for k, p in records]
        self.handler = handler
        self.next_node = next_node


def helper_trial(node, key=KEY):
    """The 0x52f5290 table lookup on one node: first matching record's
    payload, or None on a miss. A record matches when its key length
    equals the argument length and its bytes are equal (an empty key
    matches by length alone)."""
    for record_key, payload in node.records:
        if len(record_key) == len(key) and record_key == key:
            return payload
    return None


def walker(node, key=KEY):
    """The 0x514ba10 walker: step to the next node first, then repeat
    the handler/helper rule without bound. Returns the handler result,
    a helper payload, or None when the walk reaches a null node."""
    current = node.next_node if node is not None else None
    while current is not None:
        if current.handler is not None:
            return current.handler(current, key)
        hit = helper_trial(current, key)
        if hit is not None:
            return hit
        current = current.next_node
    return None


def blockcache_lookup(head, key=KEY):
    """The 0x514e550 window: eight inline trials, then walker
    delegation. Returns the handler result, a helper payload, or None
    when the chain ends (null next node) or the walker exhausts it."""
    if head is None:
        raise NullHeadError("head node is null; the binary dereferences "
                            "it without a guard")
    current = head
    for trial in range(INLINE_TRIALS):
        if current.handler is not None:
            return current.handler(current, key)
        hit = helper_trial(current, key)
        if hit is not None:
            return hit
        # After the eighth trial there is no inline next step: the
        # window delegates to the walker with the current node, and
        # the walker steps to the next node first.
        if trial == INLINE_TRIALS - 1:
            return walker(current, key)
        nxt = current.next_node
        if nxt is None:
            return None
        current = nxt
    return None


def build_chain(specs):
    """Build a chain from a list of specs, head first.

    Each spec is (records, handler): records is a list of (key,
    payload) pairs, handler is None (sentinel) or a callable. Returns
    the head node, or None for an empty list.
    """
    head = None
    for records, handler in reversed(specs):
        head = ChainNode(records=records, handler=handler, next_node=head)
    return head
