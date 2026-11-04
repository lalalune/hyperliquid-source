"""Model of node #115 routine 0x5d51ea0: guarded chain walk.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes two arguments: a destination pointer in rdi and
a source object pointer in rsi. It returns the destination pointer.
End to end, in order:

1. Gate: read the qwords at source +0x418 and +0x420. When BOTH
   are zero, the destination is zeroed (bytes 0-5 and 8-15; bytes
   6-7 are never written) and the routine returns at once: no
   setup call, no walk, no virtual call, no temp disposal.
2. Setup (only when the gate passes): call 0x60a1500 with
   (source +0x330, source); then call 0x603d410 with (the stack
   temp slot at rsp, the first call's result). Both callees are
   opaque; only the argument lists and order are pinned. The
   second call fills a 32-byte string-shaped temp (pointer at
   +0x00, capacity-or-inline-buffer at +0x10).
3. Chain walk: start from the node at source +0x318 and follow
   each node's +0x48 link. Each node's vtable slot at +0x118 is
   compared with the previous node's slot, where the first node
   is compared with the sentinel qword at 0x64ed1b8. The first
   node whose slot differs from its predecessor's is called
   through that slot with (destination, node, temp slot). If the
   first four nodes all carry the same slot, the fifth node is
   called through its slot unconditionally. At most five nodes
   are visited.
4. Temp disposal, std::string SSO rule: if the temp pointer
   differs from the temp's own +0x10 slot address (heap form),
   delete it with size capacity + 1; inline form frees nothing.
   The temp size field at +0x08 is never read.

The routine's landing-pad entry at 0x5d51fdf jumps to the
cleanup block at 0x5d51e6e, which disposes the temp string
(std::string _M_dispose on the temp slot) and resumes unwinding;
the exception path is recorded, not modelled as a normal return.

NOT modelled: what the setup or virtual callees do with their
arguments, what the source fields, the nodes, or the sentinel
denote, or behaviour on dangling pointers. A null source, a
null head node, or a null link on a chain that has not yet
diverged raises, matching the binary's unconditional reads.
"""

GATE_OFFSETS = (0x418, 0x420)
SETUP_FIELD_OFFSET = 0x330
HEAD_OFFSET = 0x318
NODE_NEXT_OFFSET = 0x48
VTABLE_SLOT_OFFSET = 0x118
SENTINEL_ADDRESS = 0x64ED1B8
MAX_NODES = 5


class TempString:
    """A 32-byte string-shaped temp: pointer, capacity, inline flag."""

    def __init__(self, pointer, capacity, inline):
        self.pointer = pointer
        self.capacity = capacity
        self.inline = inline

    @property
    def slot_address(self):
        # The temp's own +0x10 slot address; only its identity
        # matters: inline means pointer == slot address.
        return "temp+0x10" if self.inline else "heap-buffer"


class Node:
    """One chain node: a vtable slot value and the next node."""

    def __init__(self, name, slot, next_node=None):
        self.name = name
        self.slot = slot
        self.next_node = next_node


def chain_walk(dest, source, sentinel, setup1, setup2, virtual, events):
    """Run the pinned behaviour.

    dest: bytearray of at least 16 bytes (the destination struct).
    source: dict with "field_0x418", "field_0x420" (ints),
    "field_0x330" (opaque) and "head" (Node or None).
    sentinel: the sentinel slot value (qword at 0x64ed1b8).
    setup1: callable(source_plus_0x330, source) -> opaque value.
    setup2: callable(temp_slot, setup1_value) -> TempString.
    virtual: callable(dest, node, temp).
    events: list the model appends observable steps to, in order.

    Returns "returned" on every normal path; the event list and
    the destination bytes are what distinguish the paths.
    """
    if source is None:
        raise ValueError("null source pointer")
    if dest is None:
        raise ValueError("null destination pointer")
    if source["field_0x418"] == 0 and source["field_0x420"] == 0:
        for index in list(range(0, 6)) + list(range(8, 16)):
            dest[index] = 0
        events.append("zero path: destination bytes 0-5, 8-15 zeroed")
        return "returned"
    value = setup1(source["field_0x330"], source)
    events.append("setup1 called (0x60a1500)")
    temp = setup2("temp-slot", value)
    events.append("setup2 called (0x603d410)")
    node = source["head"]
    previous_slot = sentinel
    for index in range(MAX_NODES):
        if node is None:
            raise ValueError("null chain node at position %d" % index)
        if index < MAX_NODES - 1 and node.slot == previous_slot:
            previous_slot = node.slot
            node = node.next_node
            continue
        virtual(dest, node, temp)
        events.append("virtual called on node %s (vtable slot 0x118)"
                      % node.name)
        break
    if not temp.inline:
        events.append("delete temp pointer size %d" % (temp.capacity + 1))
    else:
        events.append("temp inline: no free")
    return "returned"
