"""Python model of node #115 routine 0x5d54630 (RE-001 work item).

The routine appends a freshly allocated 0x48-byte node to the holder's
anchored list, after walking a five-deep handler chain to produce the
node's payload. The model follows the disassembly literally: every
conditional call, field write and link step below is a line in the
whole-function excerpt research/work-items/RE-001-node-link-54630-115/
main.txt. Mutex helpers are recorded by call shape only; their
internal bodies are not pinned here.

Arguments (System V): rdi = holder, esi = one byte stored at node
+0x40, edx = flag byte selecting the mutex entry helper.

Chain walk (holder +0x540 head, +0x20 next link, +0xc0 slot):
  node 0's slot is compared against the qword at 0x64ed3e8; each
  later node's slot is compared against the previous node's slot.
  The first node whose slot differs has its slot called; if all four
  compared slots match, the fifth node's slot is called
  unconditionally. The called handler receives (out_pair, node,
  aux_slot): it fills the two-element out pair and the aux slot.

After the produce call the out pair's second element is freed with
delete[] when non-null, and the aux value becomes node +0x30.

Mutex entry: flag != 0 calls 0x606ca40 on holder +0x700, flag == 0
calls 0x60d5390 on the same object. If holder +0xc98 is zero the
node is destroyed through its vtable slot 0x20 (relocation value
0x5d54f30) and NULL is returned; on that path the flag != 0 case
first calls 0x60d52f0 (release), while the flag == 0 case destroys
directly with no release call. That asymmetry is literal.

Otherwise node +0x08 is: the return of the holder's slot-0x480
function when that slot differs from the qword at 0x64ed550;
[[holder +0x68] + 0x120] when holder +0x17b2 is zero; else
[[holder +0x68] + 0x108].

Node layout: +0x00 vptr 0x64c92d0, +0x10 = 1, +0x18 =
holder +0x11e0, +0x20 = [holder +0x11f8] (anchor tail), +0x28 =
holder +0x11e0, +0x30 = aux, +0x38 = -1, +0x40 = esi byte.
Splice (literal): [tail + 0x20] = node, [tail + 0x18] = node,
holder +0x1228 count += 1. On success with flag != 0 the routine
calls 0x60d52f0 (release) and returns the node; with flag == 0 it
returns the node with no release call.
"""

VPTR = 0x64C92D0
NODE_SIZE = 0x48
CHAIN_HEAD_OFFSET = 0x540
MUTEX_OFFSET = 0x700
COUNT_OFFSET = 0x1228
GLOBAL_SLOT_ADDR = 0x64ED3E8
GLOBAL_SLOT480_ADDR = 0x64ED550


class Node:
    """One list node. slot_id is the comparable +0xc0 function value;
    slot_fn is the opaque handler callable behind that value."""

    def __init__(self, slot_id=None, slot_fn=None, next_node=None):
        self.slot_id = slot_id
        self.slot_fn = slot_fn
        self.next = next_node
        self.vptr = None
        self.f10 = None
        self.f08 = None
        self.f18 = None
        self.f20 = None
        self.f28 = None
        self.f30 = None
        self.f38 = None
        self.f40 = None


class Holder:
    def __init__(self, chain_head, global_slot, c98_nonzero,
                 slot480_value, slot480_global, slot480_fn,
                 flag_17b2_zero, obj68_108, obj68_120,
                 anchor_addr, anchor_tail):
        self.chain_head = chain_head
        self.global_slot = global_slot
        self.c98_nonzero = c98_nonzero
        self.slot480_value = slot480_value
        self.slot480_global = slot480_global
        self.slot480_fn = slot480_fn
        self.flag_17b2_zero = flag_17b2_zero
        self.obj68_108 = obj68_108
        self.obj68_120 = obj68_120
        self.anchor_addr = anchor_addr
        self.anchor_tail = anchor_tail
        self.count = 0
        self.mutex_calls = []
        self.freed = []
        self.destroyed = []


def walk_chain(head, global_slot):
    """Return the chain node whose handler the routine calls."""
    node = head
    prev = global_slot
    for i in range(5):
        if i == 4 or node.slot_id != prev:
            return node
        prev = node.slot_id
        node = node.next
    raise AssertionError("chain shorter than five nodes")


def link_node(holder, byte_arg, flag):
    """Run the routine. Returns the new Node, or None on destroy."""
    chain_node = walk_chain(holder.chain_head, holder.global_slot)
    out_pair = [None, None]
    aux = [None]
    chain_node.slot_fn(out_pair, chain_node, aux)
    if out_pair[1] is not None:
        holder.freed.append(out_pair[1])
    node = Node()
    node.vptr = VPTR
    node.f10 = 1
    if flag != 0:
        holder.mutex_calls.append(("acquire_606ca40", MUTEX_OFFSET))
    else:
        holder.mutex_calls.append(("entry_60d5390", MUTEX_OFFSET))
    if not holder.c98_nonzero:
        if flag != 0:
            holder.mutex_calls.append(("release_60d52f0", MUTEX_OFFSET))
        holder.destroyed.append(node)
        return None
    if holder.slot480_value != holder.slot480_global:
        node.f08 = holder.slot480_fn(holder)
    elif holder.flag_17b2_zero:
        node.f08 = holder.obj68_120
    else:
        node.f08 = holder.obj68_108
    tail = holder.anchor_tail
    node.f18 = holder.anchor_addr
    node.f20 = tail
    node.f28 = holder.anchor_addr
    node.f30 = aux[0]
    node.f38 = -1
    node.f40 = byte_arg & 0xFF
    tail.f20 = node
    tail.f18 = node
    holder.count += 1
    if flag != 0:
        holder.mutex_calls.append(("release_60d52f0", MUTEX_OFFSET))
    return node
