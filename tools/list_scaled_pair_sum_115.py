"""Model of node #115 list scaled-pair sum 0x5f13090.

The window takes one list header (rdi) plus two arguments (rsi,
rdx) that it forwards unchanged to every per-element call. The
header's qword at + 0x00 is the first node; each node's qword at
+ 0x00 is the next node and its qword at + 0x10 is its payload.
The list ends when a node's next pointer equals the header
address itself, and an empty list is a header whose first node
already equals the header.

For each node the window calls 0x5f09a50 (the scaled pair total)
with (payload, rsi, rdx). That callee returns a pair: rax is the
scaled value and rdx is the clamped total. The window accumulates
both components separately across the whole list, in 64-bit
wrapping arithmetic, and returns (scaled sum, clamped sum). An
empty list returns (0, 0).

The per-element callee is taken by contract here: the caller
supplies a callable taking (payload, arg1, arg2) and returning a
(scaled, clamped) pair. What the list elements are and what the
pass-through arguments mean is not established by this window
alone and is recorded as an unknown in the work-item README; the
model forwards the arguments unchanged and requires a
header-terminated chain, since the window itself has no guard
against a missing terminator.
"""

MASK = (1 << 64) - 1

CALLEE = 0x5F09A50


class ListNode:
    """One list node: payload at + 0x10, next pointer at + 0x00."""

    def __init__(self, payload, next_node=None):
        self.payload = payload
        self.next_node = next_node


class ListHeader:
    """The list header: its first-node slot is + 0x00.

    An empty list is a header whose first node is the header
    itself, exactly the window's empty test.
    """

    def __init__(self, first=None):
        self.first = self if first is None else first


def list_scaled_pair_sum(header, pair_total, arg1, arg2):
    """Walk the header-terminated list and sum both callee components.

    pair_total(payload, arg1, arg2) must return a (scaled,
    clamped) pair, the contract of 0x5f09a50. Returns
    (scaled_sum, clamped_sum) in 64-bit wrapping arithmetic.
    """
    scaled_sum = 0
    clamped_sum = 0
    node = header.first
    guard = 0
    while node is not header:
        if node is None:
            raise ValueError("list chain does not terminate at the header")
        guard += 1
        if guard > 1 << 20:
            raise ValueError("list chain does not terminate at the header")
        scaled, clamped = pair_total(node.payload, arg1, arg2)
        scaled_sum = (scaled_sum + scaled) & MASK
        clamped_sum = (clamped_sum + clamped) & MASK
        node = node.next_node
    return (scaled_sum, clamped_sum)
