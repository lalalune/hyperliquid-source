"""Model of node #115 routine 0x5d58810: timestamp guard.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes three arguments: an out Status pointer in rdi,
a factory pointer in rsi, and an object pointer in rdx. It returns
the out Status. End to end, in order:

1. Resolve. When the object (rdx) is non-null it is used as-is
   and the factory is never read. When it is null, the factory
   vtable slot 0x3e8 is read: when the slot equals the default
   getter 0x5d48510 (``mov 0x740(%rdi),%rax; ret``), the object
   is *(factory+0x740) (the load is inlined); otherwise the slot
   is called with the factory and its return is the object.
2. Describe. The virtual method at vtable slot 0x28 of the
   object is called; its result P is read at +0x28.
3. Gate. When P+0x28 is null the routine writes an empty OK
   status (code 0, subcode 0, no message) and returns. No
   message is built and the name slot is never called.
4. Name. The virtual method at vtable slot 0x10 of the object
   is called; it returns a pointer to a {ptr:+0, len:+8} view.
5. Message. An ostringstream assembles
   "cannot call this method on column family " + name +
   " that enables timestamp", copied into a temp string.
6. Build. Helper 0x61cf670 writes the status: code 4
   (InvalidArgument), subcode 0, message pointer at +0x08 to a
   new heap buffer holding the first view, plus ": " and the
   second view only when the second view is non-empty; the old
   message buffer is freed with delete[] when non-null. The
   second view here is {ptr 0x4376fd, len 0}: the byte at
   0x4376fd is 0x00 and the oneshot.rs path text that follows at
   +1 is never copied, so the message is exactly the first view.

The routine's landing-pad entries at 0x5d58aa5, 0x5d58aae and
0x5d58ab4 dispose the temp string and/or the ostringstream and
resume unwinding; the exception path is recorded, not modelled
as a normal return. The builder's cleanup block at 0x61cf650
frees the old message buffer and resumes unwinding.

NOT modelled: what the describe result P or its +0x28 field
denote, what the factory's +0x740 object denotes, which
concrete column-family names occur, or behaviour on dangling
pointers. A null object pointer raises, matching the binary's
unconditional vtable read; a null describe result raises too.
Status bytes +0x06..+0x07 are never written by either path and
are not modelled.
"""

PREFIX = "cannot call this method on column family "
SUFFIX = " that enables timestamp"
CODE_OK = 0
CODE_INVALID_ARGUMENT = 4
SUBCODE = 0
RESOLVE_SLOT = 0x3E8
DESCRIBE_SLOT = 0x28
NAME_SLOT = 0x10
FACTORY_FIELD = 0x740
DESCRIBE_FIELD = 0x28
DEFAULT_GETTER = 0x5D48510
SECOND_VIEW_PTR = 0x4376FD


class Status:
    """A 16-byte status: code at +0x00, subcode at +0x01,
    message pointer at +0x08 (None when there is no message)."""

    def __init__(self, code, subcode, msg):
        self.code = code
        self.subcode = subcode
        self.msg = msg

    def __eq__(self, other):
        return (isinstance(other, Status) and self.code == other.code
                and self.subcode == other.subcode
                and self.msg == other.msg)

    def __repr__(self):
        return "Status(%d, %d, %r)" % (self.code, self.subcode, self.msg)


def build_status(view1, view2):
    """The 0x61cf670 builder: code 4, subcode 0, message is view1,
    plus ': ' and view2 only when view2 is non-empty."""
    if view2:
        msg = view1 + ": " + view2
    else:
        msg = view1
    return Status(CODE_INVALID_ARGUMENT, SUBCODE, msg)


def timestamp_guard(factory, obj, describe, name, events):
    """Run the pinned behaviour.

    factory: dict with "slot_0x3e8" ("default" or a callable
    taking the factory) and "field_0x740" (the object the
    default getter returns). Only read when obj is None.
    obj: the object, or None to take the resolve path.
    describe: callable(obj) -> dict with "field_0x28"
    (None or an opaque non-null marker).
    name: callable(obj) -> str, the column-family name view.
    events: list the model appends observable steps to, in order.

    Returns the Status; the event list is what distinguishes
    the paths.
    """
    if obj is None:
        if factory is None:
            raise ValueError("null object and null factory")
        slot = factory["slot_0x3e8"]
        if slot == "default":
            obj = factory["field_0x740"]
            events.append("resolve: default getter *(factory+0x740)")
        else:
            obj = slot(factory)
            events.append("resolve: vtable slot 0x3e8 called")
        if obj is None:
            raise ValueError("resolve returned null object")
    target = describe(obj)
    events.append("describe called (vtable slot 0x28)")
    if target is None:
        raise ValueError("describe returned null")
    if target["field_0x28"] is None:
        events.append("gate: +0x28 null, OK status")
        return Status(CODE_OK, SUBCODE, None)
    events.append("gate: +0x28 non-null, building message")
    family = name(obj)
    events.append("name called (vtable slot 0x10)")
    message = PREFIX + family + SUFFIX
    events.append("message assembled")
    return build_status(message, "")
