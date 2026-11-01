"""Model of node #94's wrapper-chain dispatch (RE-001).

Evidence: research/work-items/RE-001-chain-dispatch-94/ (records.json
plus verbatim whole-function objdump excerpts), bound to node #94
(SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).

The binary facts modelled here:

* ``current_head`` (0x514df80) returns ``[[outer + 0x788] + 0x6b0]``.
* Each getter (0x514dfa0 slot 0x70, 0x514e030 slot 0x78, 0x514e0c0
  slot 0x98) resolves through a chain of wrapper nodes. A wrapper
  holds an inner-object pointer at +0x00 and the next wrapper at
  +0x38; the dispatch slot of a wrapper is ``[inner + slot]``.
* The walk compares each visited wrapper's slot against the
  contents of the getter's sentinel cell. While the slot equals
  the sentinel it advances, at most four times; the first
  non-sentinel slot is called with the wrapper and its result is
  stored. The fifth node is called unconditionally. A null head
  returns 0 with the output untouched.

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

HEAD_CHAIN = (0x788, 0x6B0)


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


def current_head(outer):
    """Return ``[[outer + 0x788] + 0x6b0]``.

    ``outer`` is a mapping ``{0x788: sub-object}`` and the
    sub-object is a mapping ``{0x6b0: head-or-None}``, mirroring
    the two loads in 0x514df80.
    """
    sub = outer[0x788]
    return sub[0x6B0]


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


def resolve(outer, slot_offset, sentinel):
    """Resolve through the getter for ``slot_offset`` (0x70/0x78/0x98).

    ``slot_offset`` selects the getter only; the walk itself is
    identical for all three, as the three binary functions agree
    instruction for instruction apart from the slot offset and the
    sentinel cell. The sentinel cell address for the getter is
    available as ``SENTINEL_CELLS[slot_offset]``.
    """
    if slot_offset not in SLOT_OFFSETS:
        raise ValueError("unknown dispatch slot: %#x" % slot_offset)
    return resolve_chain(current_head(outer), sentinel)
