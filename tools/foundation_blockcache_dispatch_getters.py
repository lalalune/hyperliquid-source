"""Model of node #94's BlockCache dispatch getters (RE-001).

Evidence: research/work-items/RE-001-blockcache-dispatch-getters-94/
(records.json plus verbatim whole-function objdump excerpts), bound
to node #94 (SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).

The binary facts modelled here:

* Each getter (0x514e7e0 slot 0x70, 0x514e870 slot 0x78, 0x514e900
  slot 0x98) takes an outer object in rdi and an output pointer in
  rsi, and first calls the BlockCache chain lookup 0x514e550 on the
  outer object. That lookup is bound by
  research/work-items/RE-001-blockcache-chain-lookup-94/ and is cited
  here as a callee only: it returns the matching record's +0x20
  first qword, or 0 on a miss.
* A null lookup result returns 0 with the output untouched.
* Otherwise the getter walks a chain of wrapper nodes. A wrapper
  holds an inner-object pointer at +0x00 and the next wrapper at
  +0x38; the dispatch slot of a wrapper is ``[inner + slot]``.
* The walk compares each visited wrapper's slot against the
  contents of the getter's sentinel cell (0x5777a28 for slot 0x70,
  0x5777a78 for slot 0x78, 0x5777a38 for slot 0x98 — the same cells
  the current-head getters of RE-001-chain-dispatch-94 compare
  against, shared here, not re-claimed). While the slot equals the
  sentinel it advances, at most four times; the first non-sentinel
  slot is called with the wrapper and its result is stored at the
  output, and the getter returns 1. The fifth node is called
  unconditionally.
* The three getters agree instruction for instruction apart from
  the slot offset, the sentinel cell, and their call-site
  addresses; the walk itself is identical for all three.

The model deliberately does not guess what the wrappers, inner
objects or dispatched values mean, nor what the sentinel cells
hold at runtime: the sentinel is a caller-supplied value compared
by identity, exactly as the code compares against the cell
contents. A chain that runs out of nodes while every slot still
equals the sentinel has no pinned binary result (the code would
dereference the null next pointer), so the model raises
``ChainExhausted`` instead of inventing one.
"""

MAX_SENTINEL_SKIPS = 4

SLOT_OFFSETS = (0x70, 0x78, 0x98)

SENTINEL_CELLS = {
    0x70: 0x5777A28,
    0x78: 0x5777A78,
    0x98: 0x5777A38,
}

GETTER_STARTS = {
    0x70: 0x514E7E0,
    0x78: 0x514E870,
    0x98: 0x514E900,
}

LOOKUP_ADDRESS = 0x514E550


class ChainExhausted(Exception):
    """The chain ended while every slot still equalled the sentinel."""


class Wrapper:
    """One wrapper node: an inner dispatch object and a next link.

    ``slot`` is the dispatch function stored at ``[inner + slot]``
    for the getter being modelled; ``next_wrapper`` is the node at
    +0x38, or None at the end of the chain.
    """

    def __init__(self, slot, next_wrapper=None):
        self.slot = slot
        self.next_wrapper = next_wrapper


def resolve_chain(head, sentinel):
    """Walk the wrapper chain and call the resolved dispatch slot.

    Returns ``(found, value)``: ``(False, None)`` for a null head
    (the getter returns 0 with the output untouched), otherwise
    ``(True, slot(wrapper))`` for the first non-sentinel slot, or
    for the fifth node's slot when the first four all equal the
    sentinel. Raises ``ChainExhausted`` when the chain ends while
    every slot still equals the sentinel.
    """
    node = head
    if node is None:
        return (False, None)
    skips = 0
    while node.slot == sentinel and skips < MAX_SENTINEL_SKIPS:
        node = node.next_wrapper
        if node is None:
            raise ChainExhausted(
                "chain ended after %d sentinel nodes" % (skips + 1))
        skips += 1
    return (True, node.slot(node))


def resolve(lookup_result, slot_offset, sentinel):
    """Resolve through the getter for ``slot_offset`` (0x70/0x78/0x98).

    ``slot_offset`` selects the getter only; the walk itself is
    identical for all three, as the three binary functions agree
    instruction for instruction apart from the slot offset and the
    sentinel cell. ``lookup_result`` is the BlockCache lookup's
    return value: a wrapper node, or None on a lookup miss.
    """
    if slot_offset not in SLOT_OFFSETS:
        raise ValueError("unknown getter slot offset %#x" % slot_offset)
    return resolve_chain(lookup_result, sentinel)
