"""Model for node #94 snapshot identity-format function 0x514ed50 (RE-001).

The window builds a 0x130-byte snapshot object from a source wrapper
chain: it formats an identity string ``name@pointer#pid`` into
dest+0x20, resolves two chain dispatches into dest+0x00/+0x08, runs
two conditional side-effect dispatches, zeroes the middle block,
increments a 32-bit counter at +0x120 and stores the third argument
at +0x128. Dest+0x10 is 0 and dest+0x18 is -1 on every path.

Wrapper model: a wrapper has an ``inner`` object and a ``next``
wrapper (or None). The inner object carries a name resolver (the
+0x10 slot call), per-slot dispatch values (the code pointers the
walk compares) and per-slot handlers (the functions the walk calls
with the wrapper). Dispatch values are opaque comparable labels; the
model never invents their runtime meaning.

Stdlib only. The pid is a parameter: the window reads it from
getpid() at runtime, so no fixed value is pinned.
"""


class ChainExhausted(Exception):
    """The walk skipped past the last wrapper while still sentinel."""


class Inner:
    """One wrapper's inner object.

    ``name`` is the +0x10 call's result: a string, None, or a
    callable taking the wrapper and returning a string or None.
    ``slot_values`` maps a slot offset to its dispatch label.
    ``handlers`` maps a slot offset to a callable taking the wrapper
    and returning the dispatch result.
    """

    def __init__(self, name=None, slot_values=None, handlers=None):
        self.name = name
        self.slot_values = dict(slot_values or {})
        self.handlers = dict(handlers or {})

    def resolve_name(self, wrapper):
        if callable(self.name):
            return self.name(wrapper)
        return self.name

    def slot_value(self, slot):
        return self.slot_values.get(slot)

    def dispatch(self, slot, wrapper):
        handler = self.handlers.get(slot)
        if handler is None:
            # No handler registered: the dispatch result is the slot
            # value itself (used for sentinel/identity tests).
            return self.slot_values.get(slot)
        return handler(wrapper)


class Wrapper:
    """One chain node: an inner object plus the next wrapper."""

    def __init__(self, inner, next_wrapper=None):
        self.inner = inner
        self.next = next_wrapper


def format_pointer(address):
    """libstdc++ void* insertion: '0' for null, else '0x' + hex."""
    if address == 0:
        return "0"
    return "0x%x" % address


def format_identity(name, wrapper_address, pid):
    """The stream text: name@pointer#pid, or empty for a null name.

    A null name puts the stream into a failed state, so the later
    insertions are no-ops and the string stays empty.
    """
    if name is None:
        return ""
    return "%s@%s#%d" % (name, format_pointer(wrapper_address), pid)


def walk_dispatch(head, slot, sentinel_cell):
    """Resolve one chain dispatch the way the window does.

    Compare the first node's slot against the sentinel cell; skip
    while the slot equals the sentinel (later comparisons against
    the previous node's slot value, which provably equals the cell
    on skipped paths), at most four skips; call the fifth node
    unconditionally. Raises ChainExhausted when the chain ends while
    still skipping.
    """
    if head is None:
        raise ChainExhausted("empty chain")
    node = head
    previous_value = sentinel_cell
    for position in range(5):
        value = node.inner.slot_value(slot)
        if position == 0:
            if value != sentinel_cell:
                return node.inner.dispatch(slot, node)
        else:
            if value != previous_value:
                return node.inner.dispatch(slot, node)
        if position == 4:
            # Unconditional fifth call.
            return node.inner.dispatch(slot, node)
        previous_value = value
        node = node.next
        if node is None:
            raise ChainExhausted(
                "chain ended after %d sentinel node(s)" % (position + 1))
    raise AssertionError("unreachable")


def run_side_effect_dispatches(head, cell_88, cell_80, log=None):
    """The two conditional dispatches on the head inner object.

    Each is called with the wrapper as argument, exactly as the
    window does; return values are discarded. Returns the list of
    slots actually called (the observable record).
    """
    called = [] if log is None else log
    inner = head.inner
    for slot, cell in ((0x88, cell_88), (0x80, cell_80)):
        if inner.slot_value(slot) != cell:
            handler = inner.handlers.get(slot)
            if handler is not None:
                handler(head)
            called.append(slot)
    return called


class Snapshot:
    """The built destination object, field by field."""

    def __init__(self, dispatch70, dispatch78, text, counter, value,
                 side_calls):
        self.dispatch70 = dispatch70
        self.dispatch78 = dispatch78
        self.field_10 = 0
        self.field_18 = -1
        self.text = text
        self.zero_block = bytes(0xE0)  # dest+0x40..+0x11f
        self.counter = counter
        self.value = value
        self.side_calls = list(side_calls)

    def as_dict(self):
        return {
            "dispatch70": self.dispatch70,
            "dispatch78": self.dispatch78,
            "field_10": self.field_10,
            "field_18": self.field_18,
            "text": self.text,
            "zero_block": self.zero_block,
            "counter": self.counter,
            "value": self.value,
            "side_calls": self.side_calls,
        }


def build_snapshot(old_counter, head, value, pid, sentinels,
                   wrapper_address):
    """Build one snapshot exactly as the window does.

    ``sentinels`` maps slot offsets (0x70, 0x78, 0x88, 0x80) to the
    sentinel cell contents. ``head`` is the source wrapper;
    ``wrapper_address`` is its address for the pointer insertion.
    """
    name = head.inner.resolve_name(head)
    text = format_identity(name, wrapper_address, pid)
    dispatch70 = walk_dispatch(head, 0x70, sentinels[0x70])
    dispatch78 = walk_dispatch(head, 0x78, sentinels[0x78])
    side_calls = run_side_effect_dispatches(
        head, sentinels[0x88], sentinels[0x80])
    counter = (old_counter + 1) & 0xFFFFFFFF
    return Snapshot(dispatch70, dispatch78, text, counter, value,
                    side_calls)
