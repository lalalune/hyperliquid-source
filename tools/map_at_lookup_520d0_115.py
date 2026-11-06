"""Python model of node #115 routine 0x5d520d0 (RE-001 map-at lookup).

The routine takes an out record and a holder and returns the out
record. The model takes the holder flags and head node directly, plus
the builder, assign and delete callables, because the binary's
builders (0x5f22020, 0x5f22f80) and assign helper (0x5d49b10) are
pinned by call shape only.

Graph nodes carry kind, next (+0x10), alt (+0x18) and field (+0x28)
attributes. The sentinel is a dedicated node object; a walk that ends
with the sentinel as its candidate raises, exactly as the binary's
sentinel comparison does. A phase 1 or phase 2 walk that steps onto
the sentinel itself stops there in the model; the binary instead reads
the sentinel's kind byte at that point, which is not pinned, so that
corner is an assumption, not established semantics. The walks carry no
visited set, so a cyclic graph loops forever in the binary as in the
model.
"""


class OutOfRangeError(Exception):
    """Stands for the std::out_of_range throw with literal "map::at"."""


class Node:
    def __init__(self, kind, nxt=None, alt=None, field=0):
        self.kind = kind
        self.next = nxt
        self.alt = alt
        self.field = field


SENTINEL = Node(kind=None)


class Temp:
    """Builder temp record: flag byte, dword, word, qword."""

    def __init__(self, flag, dword=0, word=0, qword=None):
        self.flag = flag
        self.dword = dword
        self.word = word
        self.qword = qword


class Out:
    """Out record. gap stays None: bytes +0x06..+0x07 are never written."""

    def __init__(self):
        self.dword = None
        self.word = None
        self.qword = None
        self.gap = None


def _delete_temp(temp, delete, events):
    if temp.qword is not None:
        delete(temp.qword)
        events.append(("delete", temp.qword))


def _zero_path(out, temp, assign, delete, events):
    out.dword = 0
    out.word = 0
    out.qword = 0
    assign(out, temp)
    events.append(("assign",))
    _delete_temp(temp, delete, events)


def map_at_lookup(flag0, flag1, head, builder, assign, delete):
    """Run the lookup. Returns (out, events).

    flag0: dword at H+0x5d0; flag1: dword at H+0x5d4.
    head: first graph node, or None for a null head pointer.
    builder(tag, field): stands for 0x5f22020 (tags 0, 1) and
        0x5f22f80 (tag 2); returns a Temp.
    assign(out, temp): stands for 0x5d49b10.
    delete(pointer): stands for the delete[] call on a temp qword.
    events: ("build", tag, field), ("assign",) and ("delete", pointer)
        in binary order.
    """
    events = []
    out = Out()
    head_now = head
    # Phase A: +0x10 chain to the last non-null node, kind must be 0.
    if flag0 != 0:
        if head_now is None:
            raise OutOfRangeError("map::at")
        cur = head_now
        while True:
            last = cur
            cur = cur.next
            if cur is None:
                break
        if last is SENTINEL:
            raise OutOfRangeError("map::at")
        if last.kind != 0:
            raise OutOfRangeError("map::at")
        temp = builder(0, last.field)
        events.append(("build", 0, last.field))
        if temp.flag != 0:
            _zero_path(out, temp, assign, delete, events)
            return out, events
        _delete_temp(temp, delete, events)
        head_now = head
    # Phase 1: kind-0 nodes step via alt, kind-nonzero nodes are
    # candidates descending via next; candidate kind must be <= 1.
    if flag1 != 0:
        if head_now is None:
            raise OutOfRangeError("map::at")
        cand = SENTINEL
        cur = head_now
        while True:
            if cur is SENTINEL:
                break
            if cur.kind == 0:
                nxt = cur.alt
                if nxt is None:
                    break
                cur = nxt
            else:
                cand = cur
                nxt = cur.next
                if nxt is None:
                    break
                cur = nxt
        if cand is SENTINEL:
            raise OutOfRangeError("map::at")
        if cand.kind > 1:
            raise OutOfRangeError("map::at")
        temp = builder(1, cand.field)
        events.append(("build", 1, cand.field))
        if temp.flag != 0:
            _zero_path(out, temp, assign, delete, events)
            return out, events
        _delete_temp(temp, delete, events)
        head_now = head
    # Phase 2: kind-at-most-1 nodes step via alt, kind-above-1 nodes
    # are candidates descending via next; candidate kind must be <= 2.
    if head_now is None:
        raise OutOfRangeError("map::at")
    cand = SENTINEL
    cur = head_now
    while True:
        if cur is SENTINEL:
            break
        if cur.kind <= 1:
            nxt = cur.alt
            if nxt is None:
                break
            cur = nxt
        else:
            cand = cur
            nxt = cur.next
            if nxt is None:
                break
            cur = nxt
    if cand is SENTINEL:
        raise OutOfRangeError("map::at")
    if cand.kind > 2:
        raise OutOfRangeError("map::at")
    temp = builder(2, cand.field)
    events.append(("build", 2, cand.field))
    out.dword = temp.dword
    out.word = temp.word
    out.qword = temp.qword
    return out, events
