"""Node #115 sentinel chain dispatch 0x5d2efc0 / 0x5d2ef10 / 0x5d2f070.

RE-001 work item. These three functions are the default (sentinel)
implementations of the three vtable slots mapped by the chain-walk
getters: slot 0x70, slot 0x78, and slot 0x98. Each sentinel's global
holds its own address at runtime (R_X86_64_RELATIVE relocation), so a
node whose slot equals the sentinel is a node that still uses the
default implementation.

Each sentinel takes a chain node in rdi and walks the chain linked
through each node's +0x38 field. The walk rule, stated literally from
the disassembly, is identical for all three sentinels (only the slot
offset and the sentinel identity differ):

    prev = SENTINEL[slot]          # the sentinel's own address
    node = receiver
    for i in range(1, 10):         # at most nine nodes are touched
        node = node.next
        t = slot(node)
        if i == 9 or t != prev:    # first differing slot wins; the 9th
            return t(node)          # node's slot is taken unconditionally
        prev = t

The differing slot is tail-jumped to, so every argument the sentinel
received passes through to it unchanged, with rdi replaced by the
differing node. The receiver's own slot is never read: the walk starts
at the receiver's +0x38 successor. The domain meaning of the chain
and the slots is not claimed; only the dispatch rule is.

The model takes plain data: a node is {"slot_id": int,
"handler": callable, "next": node | None}. A missing key raises
KeyError, mirroring the native code's unchecked dereferences. A chain
that runs out of nodes before the walk resolves raises ValueError:
the native code would dereference a null vtable pointer there, so the
model refuses rather than inventing a result.
"""

SENTINELS = {0x70: 0x5D2EFC0, 0x78: 0x5D2EF10, 0x98: 0x5D2F070}

MAX_NODES = 9


def run_sentinel(receiver, slot_offset):
    """Run one sentinel dispatch. `slot_offset` must be 0x70, 0x78, or 0x98.

    Returns the result of the first slot that differs from its
    predecessor (the first node's slot is compared against the
    sentinel itself), or of the ninth node's slot when the first
    eight all match their predecessor.
    """
    sentinel = SENTINELS[slot_offset]
    node = receiver
    prev = sentinel
    for i in range(1, MAX_NODES + 1):
        node = node["next"]
        if node is None:
            raise ValueError("chain exhausted before the dispatch resolved")
        slot_id = node["slot_id"]
        if i == MAX_NODES or slot_id != prev:
            return node["handler"](node)
        prev = slot_id
    raise AssertionError("unreachable")
