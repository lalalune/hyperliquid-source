"""Python model of node #94's WAL replay orchestrator (0x520e1b0..0x520e7e3).

RE-001 work item. The model pins the orchestrator's control flow exactly
as observed: out init, two caller-loop replay calls, pending drain,
getter call, ten-comparison handler-chain resolution, predicate
dispatch, threshold rule with its devirtualized known hook, reserve,
record partition with both arms, and teardown/epilogue order. Callees
whose internals are not pinned (caller loop, getter, parse variants,
log helper, reserve/grow/destroy helpers, chain handlers, virtual
slots) are injected callables, so the model tests the orchestrator,
not its callees. Chain handlers are modeled as callables taking the
getter string and returning a HandlerResult; the binary passes a
result struct in rdi and the getter string in rdx.

Status struct (binary layout): u32 code at +0, u16 flags at +4, owning
raw char pointer message at +8. ``byte0`` is the low byte of the code;
only it is tested. Transfers into out are moves: the source message is
cleared and the destination's old message is freed.

Known hook identities (resolved via R_X86_64_RELATIVE relocations):
  KNOWN_E8 = 0x50a97b0 (first chain-hook expectation)
  KNOWN_18 = 0x5208e00 (known +0x18 slot; body is: return arg +0x08)
  KNOWN_10 = 0x5209bd0 (known +0x10 slot; parse path instead of a call)
"""

KNOWN_E8 = 0x50A97B0
KNOWN_18 = 0x5208E00
KNOWN_10 = 0x5209BD0

LOG_FILE = "db/wal_manager.cc"
LOG_LATEST = "[%s:82] Latest Archived log: %lu"
LOG_MOVED = "[%s:95] %s already moved to archive"


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


def move_into(dst, src, events):
    """Move-assign src into dst: old message freed, source cleared."""
    old = dst.message
    dst.code = src.code
    dst.flags = src.flags
    dst.message = src.message
    src.code = 0
    src.flags = 0
    src.message = None
    if old is not None:
        events.append(("free_msg", old))


class Vec:
    """A vector: items list plus capacity (array retained on drain)."""

    def __init__(self, items=(), capacity=0):
        self.items = list(items)
        self.capacity = max(capacity, len(self.items))

    def __len__(self):
        return len(self.items)


class Link:
    """A chain link: object pointer at +0x00, next link at +0x48."""

    def __init__(self, obj, nxt=None):
        self.obj = obj
        self.next = nxt


class ChainObj:
    """An object carrying a +0xe8 handler hook."""

    def __init__(self, hook):
        self.hook = hook


class Elem:
    """A record element: +0x08 value, +0x10 u32 selector, virtual slots."""

    def __init__(self, field08, field10=0, hook18=KNOWN_18, hook10=KNOWN_10):
        self.field08 = field08
        self.field10 = field10 & 0xFFFFFFFF
        self.hook18 = hook18
        self.hook10 = hook10


class Ctx:
    """Context struct: only the fields this function reads."""

    def __init__(self, f148=None, chain_head=None, logger=None):
        self.f148 = f148
        self.chain_head = chain_head
        self.logger = logger


class HandlerResult:
    """The chain handler's result struct: code byte, detail pointer."""

    def __init__(self, code, detail=None):
        self.code = code & 0xFF
        self.detail = detail


class Callbacks:
    """Injectable callees; each records its calls in ``events``.

    Override any method to script behavior. Defaults: caller_loop
    writes a zero status and appends nothing; getter returns "";
    reserve grows capacity to at least n; grow appends the element;
    parse variants write "parsed:<field08>" into the out cell; the
    log and destroy calls only record events.
    """

    def __init__(self):
        self.events = []

    def caller_loop(self, status_out, ctx, arg3, records, file_type):
        self.events.append(("caller_loop", file_type))
        status_out.code = 0
        status_out.flags = 0
        status_out.message = None

    def getter(self, f148):
        self.events.append(("getter", f148))
        return ""

    def destroy(self, elem):
        self.events.append(("destroy", elem))

    def reserve(self, vec, count):
        self.events.append(("reserve", count))
        vec.capacity = max(vec.capacity, count)

    def grow(self, vec, elem):
        self.events.append(("grow", elem))
        vec.items.append(elem)
        vec.capacity = max(vec.capacity, len(vec.items))

    def parse_nonzero(self, out_cell, empty, field08):
        self.events.append(("parse_nonzero", field08))
        out_cell[0] = f"parsed:{field08}"

    def parse_zero(self, out_cell, empty, field08):
        self.events.append(("parse_zero", field08))
        out_cell[0] = f"parsed:{field08}"

    def log(self, level, logger, fmt, file, arg):
        self.events.append(("log", level, fmt, arg))


def resolve_chain(head):
    """Return the invoked handler: first mismatching hook, else link 11.

    Ten comparisons: link 1 vs KNOWN_E8, links 2..10 vs the previous
    link's hook. A hook is either the KNOWN_E8 identity or a callable.
    """
    link = head
    prev = KNOWN_E8
    for _ in range(10):
        hook = link.obj.hook
        if hook != prev:
            return hook
        prev = hook
        link = link.next
    return link.obj.hook


def element_value(elem):
    """Devirtualized +0x18 read: field08 when the slot is KNOWN_18."""
    if elem.hook18 == KNOWN_18:
        return elem.field08
    return elem.hook18(elem)


def epilogue(stack_records, cb):
    """Destroy each non-null stack record, then free the array."""
    for elem in stack_records.items:
        if elem is not None:
            cb.destroy(elem)
    cb.events.append(("free_array", len(stack_records.items)))


def orchestrate(out, ctx, pending, cb):
    """Run the orchestrator; returns out. See module docstring."""
    events = cb.events
    if out.message is not None:
        raise ValueError("precondition: caller must pass an empty out")
    out.code = 0
    out.flags = 0
    out.message = None

    stack_records = Vec()
    stack_status = Status()
    cb.caller_loop(stack_status, ctx, ctx.f148, stack_records, 1)
    move_into(out, stack_status, events)
    if out.byte0 != 0:
        epilogue(stack_records, cb)
        return out

    for elem in pending.items:
        if elem is not None:
            cb.destroy(elem)
    pending.items = []

    getter_str = cb.getter(ctx.f148)
    handler = resolve_chain(ctx.chain_head)
    result = handler(getter_str)
    detail = result.detail

    if result.code == 0:
        stack_status = Status()
        cb.caller_loop(stack_status, ctx, getter_str, pending, 0)
        move_into(out, stack_status, events)
        if out.byte0 != 0:
            if detail is not None:
                events.append(("free_detail", detail))
            epilogue(stack_records, cb)
            return out
    elif result.code != 1:
        if detail is not None:
            events.append(("free_detail", detail))
        epilogue(stack_records, cb)
        return out

    if len(pending.items) == 0:
        threshold = 0
    else:
        threshold = element_value(pending.items[-1])
        cb.log(1, ctx.logger, LOG_LATEST, LOG_FILE, threshold)

    cb.reserve(pending, len(stack_records.items) + len(pending.items))

    for i, elem in enumerate(list(stack_records.items)):
        assert elem is not None, "stack record slots are non-null"
        value = element_value(elem)
        if value >= threshold:
            out_cell = [""]
            if elem.hook10 == KNOWN_10:
                if elem.field10 != 0:
                    cb.parse_nonzero(out_cell, "", elem.field08)
                else:
                    cb.parse_zero(out_cell, "", elem.field08)
            else:
                elem.hook10(elem, out_cell)
            cb.log(2, ctx.logger, LOG_MOVED, LOG_FILE, out_cell[0])
        else:
            if len(pending.items) == pending.capacity:
                cb.grow(pending, elem)
            else:
                pending.items.append(elem)
            stack_records.items[i] = None

    if detail is not None:
        events.append(("free_detail", detail))
    epilogue(stack_records, cb)
    return out
