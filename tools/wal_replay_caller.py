"""Python model of node #94's WAL replay gate-and-replace caller
(0x520e830..0x520eb1c).

RE-001 work item. The model pins the caller's control flow exactly as
observed: the ctx+0x140 gate, the heap-vector allocation, the
orchestrator replay, the helper status and its move into the first
status, the 0xd0-byte object construction and slot replacement, the
heap-vector teardown, and the new object's +0x20 virtual finish.
Callees whose internals are not pinned (orchestrator, helper,
constructor, virtual calls) are injected callables, so the model tests
the caller, not its callees.

Status struct (binary layout): u32 code at +0, u16 flags at +4, owning
raw char pointer message at +8. ``byte0`` is the low byte of the code;
only it is tested. A copy leaves the source intact and does not free
the destination's old message; a move frees the old destination message
and zeroes the source.
"""

GATE_CODE = 3


class Status:
    """A 16-byte status struct: code (u32), flags (u16), message."""

    def __init__(self, code=0, flags=0, message=None):
        self.code = code & 0xFFFFFFFF
        self.flags = flags & 0xFFFF
        self.message = message

    @property
    def byte0(self):
        return self.code & 0xFF

    def __eq__(self, other):
        return isinstance(other, Status) and (
            self.code, self.flags, self.message) == (
            other.code, other.flags, other.message)

    def __repr__(self):
        return f"Status({self.code}, {self.flags}, {self.message!r})"


class Vec:
    """A heap vector of element pointers.

    ``items`` is the live begin..end range; ``has_array`` says whether
    the begin pointer is non-null (an empty vector has no array, so
    the teardown skips the sized array free but still frees the struct).
    """

    def __init__(self, items=(), has_array=False):
        self.items = list(items)
        self.has_array = has_array or bool(items)


class Elem:
    """A vector element: its +0x8 virtual call is ``destroy``."""

    def __init__(self, name):
        self.name = name

    def destroy(self, events):
        events.append(("destroy_elem", self.name))


class Obj:
    """An object in the replaced slot.

    ``destroy`` is the +0x8 virtual call; ``finish`` is the +0x20
    virtual call that writes the out status.
    """

    def __init__(self, name, finish_status=None):
        self.name = name
        self.finish_status = finish_status or Status()

    def destroy(self, events):
        events.append(("destroy_obj", self.name))

    def finish(self, out, events):
        events.append(("finish_obj", self.name))
        out.code = self.finish_status.code
        out.flags = self.finish_status.flags
        out.message = self.finish_status.message


class Slot:
    """A pointer slot holding one object (or None)."""

    def __init__(self, obj=None):
        self.obj = obj


class SlotPtr:
    """A pointer to a slot, as passed to the constructor callee."""

    def __init__(self, content):
        self.content = content


class Ctx:
    """The context struct, reduced to the fields this window uses."""

    def __init__(self, flag=0, field08=None, field158=None):
        self.flag = flag & 0xFF
        self.field08 = field08
        self.field158 = field158


def copy_status(dst, src):
    """Copy code, flags and message; source intact, old dst not freed."""
    dst.code = src.code
    dst.flags = src.flags
    dst.message = src.message


def move_status(dst, src, events):
    """Move src into dst: old dst message freed, source zeroed.

    The binary then checks the source message slot a second time; the
    slot was just zeroed, so that check never fires on a consistent
    move. The model performs it literally.
    """
    if dst.message is not None:
        events.append(("free_msg", dst.message))
    dst.code = src.code
    dst.flags = src.flags
    dst.message = src.message
    src.code = 0
    src.flags = 0
    src.message = None
    if src.message is not None:
        events.append(("free_msg", src.message))


def teardown(vec, events):
    """Destroy a heap vector: elements, array, then the struct."""
    for elem in vec.items:
        if elem is not None:
            elem.destroy(events)
    if vec.has_array:
        events.append(("free_array",))
    events.append(("free_vec_struct",))


def replay_caller(out, ctx, a, b_slot, c, d, orchestrator, helper,
                  constructor, events):
    """Run the caller. Returns ``out``.

    ``c`` is an object with a ``byte`` attribute (the constructor
    callee reads its first byte). ``constructor`` is called with a
    dict of the exact register and stack arguments observed.
    """
    # Phase 1: gate.
    if ctx.flag != 0:
        out.code = GATE_CODE
        out.flags = 0
        out.message = None
        return out
    # Phase 2: empty heap vector.
    heap_vec = Vec()
    # Phase 3: orchestrator replay.
    status1 = Status()
    orchestrator(status1, ctx, heap_vec, events)
    # Phase 4: nonzero orchestrator status.
    if status1.byte0 != 0:
        copy_status(out, status1)
        teardown(heap_vec, events)
        return out
    # Phase 5: helper call.
    status2 = Status()
    helper(status2, ctx, heap_vec, a, events)
    # Phase 6: status move.
    move_status(status1, status2, events)
    # Phase 7: nonzero helper status.
    if status1.byte0 != 0:
        copy_status(out, status1)
        teardown(heap_vec, events)
        return out
    # Phase 8: object construction. The -0x68 heap-vector slot is
    # cleared and the pointer is stashed in the dead status2 slot.
    stash = heap_vec
    slot_ptr = SlotPtr(stash)
    new_obj = constructor({
        "ctx": ctx,
        "heap_vec": heap_vec,
        "c_byte": c.byte,
        "ctx08": ctx.field08,
        "a": a,
        "slot_ptr": slot_ptr,
        "d": d,
        "flag": ctx.flag,
        "ctx158": ctx.field158,
    }, events)
    # Phase 9: object replacement.
    old = b_slot.obj
    if old is not None:
        old.destroy(events)
    b_slot.obj = new_obj
    # Phase 10: heap-vector teardown through the stash.
    teardown(stash, events)
    # Phase 11: virtual finish.
    new_obj.finish(out, events)
    # Phase 12: free the status1 message, return out.
    if status1.message is not None:
        events.append(("free_msg", status1.message))
        status1.message = None
    return out
