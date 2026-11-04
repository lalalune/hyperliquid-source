"""Python model of the RE-001 sequence-number time-entry insert 0x5d55670
(node #115).

Models only the established semantics from
research/work-items/RE-001-seq-time-entry-insert-55670-115/:
the routine walks the +0x20 chain from the holder's +0x540 field,
comparing each node's +0xc0 slot to the running expected value (first
the relocated global 0x5d4b100, then the previous node's slot), and
calls the first slot that differs -- or node 3's slot when nodes 0..2
all match. The chosen producer receives the out pair, the node, and
the address of the shared length slot (initialized to 0); afterwards
the heap pointer at out+0x08 is freed with delete[] when non-null.
The resolver then picks r13: when [[H]+0x320] differs from 0x5d48710
it is the return of calling that slot with the holder, otherwise it
is [[H+0x68]+0x108]. Under the lock pair (0x606ca40 acquire /
0x60d52f0 release on H+0x700, call-shape only) the consumer
0x5f391b0(H+0x18c8, r13, L) runs; a zero low return byte triggers
the log call 0x5fcf060 with the db_impl.cc file string and the
sequence-number failure format string. The landing pad (0x5d55644)
releases the lock and resumes unwinding when the consumer raises.
"""

EXPECTED_SLOT = 0x5D4B100
RESOLVER_SLOT = 0x5D48710
LOG_FILE = "db/db_impl/db_impl.cc"
LOG_FORMAT = "[%s:5963] Failed to insert sequence number to time entry: %lu -> %lu"


class Node:
    """One chain node: a +0xc0 slot value and a +0x20 next link."""

    def __init__(self, slot, next_node=None):
        self.slot = slot
        self.next_node = next_node


class Holder:
    """The holder H, reduced to the fields this routine reads."""

    def __init__(self, chain_head, inner_slot, fallback_value,
                 resolver_value=None, component="component"):
        self.chain_head = chain_head
        self.inner_slot = inner_slot
        self.fallback_value = fallback_value
        self.resolver_value = resolver_value
        self.component = component


def resolve_producer(nodes):
    """Return (index, slot) of the producer the chain walk selects.

    nodes is the 4-node chain starting at [H+0x540]. The expected
    value starts at the relocated global 0x5d4b100 and becomes the
    previous node's slot after each match.
    """
    expected = EXPECTED_SLOT
    for index, node in enumerate(nodes[:3]):
        if node.slot != expected:
            return index, node.slot
        expected = node.slot
    return 3, nodes[3].slot


def resolve_value(holder, resolver, events):
    """Return r13 per the resolver phase of the routine."""
    if holder.inner_slot != RESOLVER_SLOT:
        events.append(("resolver_call", holder.inner_slot))
        return resolver(holder)
    return holder.fallback_value


def insert(holder, producer, resolver, consumer, events):
    """Run the routine's observable behaviour; return the consumer byte.

    producer(node) returns (heap_token_or_None, length): the heap
    token is freed (delete[]) and the length is the shared slot value
    passed to the consumer and the log. consumer(target, r13, length)
    returns the low return byte; the target argument is the abstract
    H+0x18c8 value, passed through as the string "H+0x18c8".
    """
    nodes = []
    node = holder.chain_head
    for _ in range(4):
        if node is None:
            raise ValueError("chain ended before node 3")
        nodes.append(node)
        node = node.next_node
    index, _slot = resolve_producer(nodes)
    events.append(("producer", index))
    heap, length = producer(nodes[index])
    if heap is not None:
        events.append(("free", heap))
    r13 = resolve_value(holder, resolver, events)
    events.append(("acquire",))
    try:
        result = consumer("H+0x18c8", r13, length)
    except Exception:
        events.append(("release_landing",))
        events.append(("resume",))
        raise
    events.append(("release",))
    if result == 0:
        events.append(("log", LOG_FILE, LOG_FORMAT,
                       holder.component, r13, length))
    return result


def wrapper(box, producer, resolver, consumer, events):
    """The entry wrapper 0x5d55820: dereference twice, then run."""
    holder = box[0][0]
    return insert(holder, producer, resolver, consumer, events)
