"""Node #115 chain-walk getters 0x5eee5d0 / 0x5eee660 / 0x5eee6f0 with their
shared head helper 0x5eee5b0.

RE-001 work item. The head helper projects the chain head out of the outer
object:

    head(outer) = [[outer + 0x788] + 0x6b0]

Each getter takes (outer, out) and walks the chain linked through each
node's +0x38 field. A node carries one virtual slot: the qword at its
vtable + SLOT, where SLOT is 0x70, 0x78, or 0x98 depending on the getter.
The walk rule, stated literally from the disassembly, is the same for all
three getters (only the slot offset and the sentinel differ):

    prev = SENTINEL[slot]          # runtime value of the getter's global
    node = head
    if node is None: return 0      # *out is NOT written on this path
    for i in range(5):             # at most five nodes are touched
        t = slot(node)
        if i == 4 or t != prev:    # first differing slot wins; the 5th
            *out = t(node)         # node's slot is called unconditionally
            return 1
        prev = t
        node = node.next

So the getter invokes the first slot in the chain that differs from the
previous slot (the head node's slot is compared against the sentinel),
or the fifth node's slot when the first four all match their predecessor.
The invoked slot is a class-dependent virtual function: the model takes
it as a callable, exactly as the binary takes it from the node's vtable.
The sentinel itself is a real function in the binary (see records.json):
its RELATIVE relocation resolves the getter's global to 0x5d2efc0
(slot 0x70), 0x5d2ef10 (slot 0x78), or 0x5d2f070 (slot 0x98), and each
sentinel function begins by stepping to the +0x38 next node and comparing
that node's slot against the same global -- the default-delegation shape
the getters' unrolled walk mirrors. The domain meaning of the chain, the
head, and the slots is not claimed; only the walk rule is.

The model takes plain data: an outer dict {"member788": {"head6b0": node}}
where a node is {"slot_id": int, "handler": callable, "next": node | None}.
A missing key raises KeyError, mirroring the native code's unchecked
dereferences. A chain that runs out of nodes before the walk resolves
raises ValueError: the native code would dereference a null vtable
pointer there, so the model refuses rather than inventing a result.
"""

SENTINELS = {0x70: 0x5D2EFC0, 0x78: 0x5D2EF10, 0x98: 0x5D2F070}

MAX_NODES = 5


def head_value(outer):
    """Head helper 0x5eee5b0: [[outer + 0x788] + 0x6b0]."""
    return outer["member788"]["head6b0"]


def run_getter(outer, slot_offset, out):
    """Run one chain-walk getter. `out` is a 1-element list holding *out.

    Returns 1 and stores the invoked slot's result on success, or 0 with
    `out` untouched when the head is null. `slot_offset` must be one of
    0x70, 0x78, 0x98.
    """
    sentinel = SENTINELS[slot_offset]
    node = head_value(outer)
    if node is None:
        return 0
    prev = sentinel
    for i in range(MAX_NODES):
        if node is None:
            raise ValueError("chain exhausted before the walk resolved")
        slot_id = node["slot_id"]
        if i == MAX_NODES - 1 or slot_id != prev:
            out[0] = node["handler"](node)
            return 1
        prev = slot_id
        node = node["next"]
    raise AssertionError("unreachable")
