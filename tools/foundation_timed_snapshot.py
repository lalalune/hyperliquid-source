"""Node #94 timed snapshot refresh (0x514f270): RE-001 work item.

Reconstructs the established semantics of the 0x514f270 window from the
digest-bound evidence packet
``research/work-items/RE-001-timed-snapshot-94/``: a mutex-guarded,
throttle-gated snapshot refresh. The clock values, the dispatch-chain
nodes and the snapshot builder are injected as parameters, because
their runtime contents are not retained locally; everything else --
the threshold selection, the stale adjustment, the rebuild/skip
decision, the consumer walk, the commit stores and the publish copy --
is pinned by the window bytes.

Inner-object layout (offsets from the inner object, i.e. [outer+0x128]):

    +0x28   published snapshot (0x138 bytes; string slot via assign)
    +0x160  mutex A
    +0x188  working snapshot (0x138 bytes)
    +0x2c0  last snapshot clock value
    +0x2c8  last commit clock value
    +0x2d0  source wrapper for the snapshot builder
    +0x2d8  clock object (head of the +0x98 chain)

Working-snapshot layout (offsets from the snapshot base):

    +0x120  32-bit counter (incremented by the snapshot builder)
    +0x124  32-bit field incremented on the skip path only
    +0x128  raw clock value (snapshot path) / preserved otherwise
    +0x130  commit-time clock value (snapshot path only)
    +0x20   identity string (copied by assign on publish)

A dispatch chain is a list of nodes; each node is a dict with a
``slot`` value (compared against the chain sentinel) and a ``call``
callable returning a value. A node whose slot equals the sentinel is
skipped; the first non-sentinel node is called. When every node up to
the limit is a sentinel, the next node is called unconditionally; a
chain that runs out of nodes first raises :class:`ChainExhausted`,
mirroring the binary, which would dereference a null link.
"""

MASK64 = (1 << 64) - 1

# Threshold pairs selected by the window's flag byte (sbb/and/add
# sequence: count mask 0x1ea + 10, time mask 0xa21fe80 + 0x989680).
THRESHOLDS = {
    0: (500, 180000000),
    1: (10, 10000000),
}

SNAPSHOT_SIZE = 0x138
STRING_SLOT = 0x20
COUNTER_SLOT = 0x120
SKIP_COUNTER_SLOT = 0x124
CLOCK_VALUE_SLOT = 0x128
COMMIT_SLOT = 0x130

# Dispatch-chain limits pinned by the window bytes.
CLOCK_MAX_NODES = 4
CONSUMER_MAX_NODES = 11


class ChainExhausted(Exception):
    """A sentinel-only chain ran out of nodes before an unconditional call."""


def _walk_chain(nodes, sentinel, max_nodes):
    """Walk a sentinel-compared dispatch chain and call the winner.

    ``nodes`` is the ordered node list; each node maps ``slot`` to the
    value compared against ``sentinel`` and ``call`` to a zero-argument
    callable returning the dispatched value. Returns
    ``(result, nodes_visited)`` where ``nodes_visited`` counts the
    compared nodes plus the called node.
    """
    if not nodes:
        raise ChainExhausted("empty dispatch chain")
    # The first node is compared against the sentinel cell; later
    # comparisons use the first slot value, which provably equals the
    # cell on every path that reaches them.
    first = nodes[0]["slot"]
    index = 0
    while index < len(nodes) and index < max_nodes - 1:
        node = nodes[index]
        compared = sentinel if index == 0 else first
        if node["slot"] != compared:
            return node["call"](), index + 1
        index += 1
    if index < len(nodes):
        # The max_nodes-th node is called unconditionally.
        return nodes[index]["call"](), index + 1
    raise ChainExhausted(
        "chain of %d nodes exhausted at the unconditional slot" % len(nodes))


def thresholds_for(flag):
    """Return (count_limit, time_limit) for the window's flag byte."""
    return THRESHOLDS[0] if flag == 0 else THRESHOLDS[1]


class TimedSnapshot:
    """State of one inner object plus its published snapshot."""

    def __init__(self, inner):
        # ``inner`` maps field offsets to values; the working snapshot
        # and the published snapshot are bytearrays of SNAPSHOT_SIZE,
        # except the string slot, which is held separately so publish
        # can copy it by assign (deep copy) rather than by reference.
        self.inner = inner
        self.working = bytearray(SNAPSHOT_SIZE)
        self.working_string = ""
        self.published = bytearray(SNAPSHOT_SIZE)
        self.published_string = ""
        self.events = []

    def _field(self, offset):
        return self.inner.get(offset, 0)

    def _set_field(self, offset, value):
        self.inner[offset] = value & MASK64

    def _u32(self, buf, offset):
        return int.from_bytes(buf[offset:offset + 4], "little")

    def _set_u32(self, buf, offset, value):
        buf[offset:offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")

    def refresh(self, flag, clock_nodes, consumer_nodes, snapshot_builder,
                clock_sentinel, consumer_sentinel):
        """Run one refresh of the window.

        ``clock_nodes`` / ``consumer_nodes`` are the dispatch chains;
        ``snapshot_builder`` is called as ``builder(snapshot, clock_value)``
        where ``snapshot`` is a dict with ``bytes`` (bytearray),
        ``string`` (str, read/write) and ``counter`` helpers, and must
        store the raw clock value at +0x128 and the identity string.
        The binary copies the dispatch result to rcx at 0x514f34f
        before subtracting inner+0x2c8, so rcx carries the raw clock
        value, not the elapsed value; rdx carries the clock object
        [inner+0x2d8], whose use inside the builder is not pinned here.
        Returns ``"snapshot"``, ``"skip"`` or ``"noop"``.
        """
        if self.inner is None:
            return "noop"
        self.events.append("lock_a")
        count_limit, time_limit = thresholds_for(flag)
        last_snapshot = self._field(0x2C0)
        last_commit = self._field(0x2C8)
        if last_snapshot < last_commit:
            inflated = ((last_commit - last_snapshot) & MASK64) * count_limit
            inflated &= MASK64
            if inflated > time_limit:
                time_limit = inflated
            self.events.append("stale_adjust")
        clock_value, _ = _walk_chain(clock_nodes, clock_sentinel,
                                      CLOCK_MAX_NODES)
        elapsed = (clock_value - last_commit) & MASK64
        snapshot = {
            "bytes": self.working,
            "string": self.working_string,
        }
        if elapsed > time_limit:
            self._set_field(0x2C0, clock_value)
            snapshot_builder(snapshot, clock_value)
            self.working_string = snapshot["string"]
            # Consumer struct: (snapshot, 0, 0x514b120, 0x514ac60) with
            # a qword 0x100 beside it; the consumer chain is called
            # with (wrapper, struct, pointer-to-0x100).
            _walk_chain(consumer_nodes, consumer_sentinel,
                        CONSUMER_MAX_NODES)
            self.events.append("consumer_called")
            callback = snapshot.get("callback", 0)
            if callback:
                self.events.append("post_call_callback")
            # Commit: the clock head's +0x98 slot is called directly,
            # with no chain walk.
            fresh = clock_nodes[0]["call"]()
            self._set_field(0x2C8, fresh)
            self.working[COMMIT_SLOT:COMMIT_SLOT + 8] = \
                (fresh & MASK64).to_bytes(8, "little")
            decision = "snapshot"
        else:
            current = self._u32(self.working, SKIP_COUNTER_SLOT)
            self._set_u32(self.working, SKIP_COUNTER_SLOT, current + 1)
            decision = "skip"
        self.events.append("lock_b")
        # Publish: raw copy of the whole snapshot except the 32-byte
        # string object at +0x20..+0x40, which is copied by assign.
        for offset in range(0, SNAPSHOT_SIZE, 16):
            if offset in (STRING_SLOT, STRING_SLOT + 16):
                continue
            self.published[offset:offset + 16] = \
                self.working[offset:offset + 16]
        self.published_string = self.working_string
        self.events.append("unlock_b")
        self.events.append("unlock_a")
        return decision


def make_node(slot, value):
    """Build a chain node whose call returns ``value``."""
    return {"slot": slot, "call": lambda: value}
