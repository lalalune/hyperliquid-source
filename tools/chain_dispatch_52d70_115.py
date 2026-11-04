"""Model of node #115 routine 0x5d52d70: chain resolve-and-dispatch.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes one argument: an owner pointer in rdi. It never
returns normally; it ends in a tail jump to a handler resolved
from a chain. End to end, in order:

1. Acquire: call 0x60d5390 with owner +0x700. That callee is a
   no-op stub (endbr64; ret, FDE 0x60d5390..0x60d5395): the call
   returns at once and changes nothing observable.
2. Counter: the dword at owner +0x1444 is incremented by 1.
3. Head: the node pointer at owner +0x318 is read (node N0).
   Each node contributes a handler value H = *( *(node) + 0x170 ),
   and the next node is *(node + 0x48).
4. Resolve, comparing each handler against the previous one,
   starting from the previous value held in the global at
   0x64ed590. That global carries an R_X86_64_RELATIVE relocation
   with addend 0x5d4b320, so its relocated value is 0x5d4b320
   (the file bytes there are 0 only because the relocation has
   not been applied yet):
   - if H0 != 0x5d4b320, dispatch H0 with node N0;
   - else if H1 != H0, dispatch H1 with node N1;
   - else if H2 != H1, dispatch H2 with node N2;
   - else if H3 != H2, dispatch H3 with node N3;
   - else dispatch H4 with node N4, unconditionally.
5. Dispatch: tail jump (jmp *%rax or jmp *%r10) to the resolved
   handler with (rdi = node, rsi = 0x5dd6060, rdx = owner,
   rcx = 2, r8 = 0, r9 = 0). Because it is a tail jump, the
   handler returns directly to this routine's caller. The
   address in rsi is executable code (FDE 0x5dd6060..0x5dd6097);
   its body is not modelled, only its address.

NOT modelled: what the owner, the nodes, or the handlers denote;
what any dispatched handler does; what the routine at 0x5d4b320
does beyond its pinned first instructions (it walks the same
+0x48 chain and compares against the same global, per
sentinel.txt); or what the routine at 0x5dd6060 does. A null
owner, a null node or link, or a resolved handler of 0 raises
in the model: the binary would fault on the same reads, and a
tail jump to address 0 would fault too, so the model refuses
instead of inventing a dispatch. The global's relocated value
is pinned from the relocation record; a runtime write to the
global after load is not modelled.
"""

ACQUIRE_CALLEE = 0x60D5390
ACQUIRE_OFFSET = 0x700
HEAD_OFFSET = 0x318
COUNTER_OFFSET = 0x1444
LINK_OFFSET = 0x48
HANDLER_OFFSET = 0x170
GLOBAL_ADDRESS = 0x64ED590
GLOBAL_VALUE = 0x5D4B320
RSI_TARGET = 0x5DD6060
DISPATCH_COUNT = 2
MASK64 = 0xFFFFFFFFFFFFFFFF


class Node:
    """One chain node: its handler value H (the value the binary
    reads from *(node) + 0x170) and the next node, or None at
    the chain end. The double indirection through the node's
    first qword is folded into H here; the walk order and the
    comparisons are exactly the binary's."""

    def __init__(self, head, link=None):
        self.head = head & MASK64
        self.link = link

    def handler(self):
        return self.head


class Owner:
    """The routine's owner: a head node, a counter, and the
    previous handler value the global holds at entry."""

    def __init__(self, head_node, counter=0, previous=GLOBAL_VALUE):
        self.head_node = head_node
        self.counter = counter
        self.previous = previous & MASK64


def chain_dispatch(owner, events):
    """Run the pinned behaviour.

    owner: an Owner. events: list the model appends observable
    steps to, in order. Returns ("dispatched", handler, node,
    (node, RSI_TARGET, owner, 2, 0, 0)) on every normal path.
    """
    if owner is None:
        raise ValueError("null owner pointer")
    events.append("acquire stub called (0x60d5390, owner +0x700, no-op)")
    owner.counter += 1
    events.append("counter at owner +0x1444 incremented to %d"
                  % owner.counter)
    node = owner.head_node
    if node is None:
        raise ValueError("null head node at owner +0x318")
    previous = owner.previous
    for step in range(5):
        handler = node.handler()
        if step < 4:
            if handler != previous:
                events.append(
                    "step %d: handler %#x differs from previous %#x, "
                    "dispatching" % (step, handler, previous))
                return ("dispatched", handler, node,
                        (node, RSI_TARGET, owner, DISPATCH_COUNT, 0, 0))
            events.append(
                "step %d: handler %#x equals previous %#x, walking on"
                % (step, handler, previous))
            previous = handler
            node = node.link
            if node is None:
                raise ValueError(
                    "chain ends at step %d before a dispatch" % step)
        else:
            if handler == 0:
                raise ValueError(
                    "resolved handler is 0; the binary would jump to 0")
            events.append(
                "step 4: dispatching handler %#x unconditionally"
                % handler)
            return ("dispatched", handler, node,
                    (node, RSI_TARGET, owner, DISPATCH_COUNT, 0, 0))
    raise AssertionError("unreachable")
