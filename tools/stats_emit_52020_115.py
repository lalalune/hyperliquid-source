"""Model of node #115 routine 0x5d52020: statistics emit.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes one argument: an object pointer in rdi. It
returns void. End to end, in order:

1. Gate: read the pointer at object +0x548. When it is null
   the routine returns at once: no produce call, no emit call,
   no disposal.
2. Produce: call the virtual method at vtable slot 0xe8 of the
   +0x548 object, with the stack temp slot as the hidden
   string-result slot and the +0x548 pointer as the object
   argument. The callee is opaque; the model takes it as a
   caller-supplied callable that fills a 32-byte string-shaped
   temp (pointer at +0x00, capacity-or-inline-buffer at +0x10).
3. Emit: call 0x5fcf060 with (1, object +0x360 by address,
   "[%s:774] STATISTICS:\\n %s", "db/db_impl/db_impl.cc",
   temp pointer). The callee is opaque; only the argument list
   and order are pinned.
4. Temp disposal, std::string SSO rule: if the temp pointer
   differs from the temp's own +0x10 slot address (heap form),
   delete it with size capacity + 1; inline form frees nothing.
   The temp size field at +0x08 is never read.

The routine's landing-pad entry at 0x5d520b5 jumps to the
cleanup block at 0x5d51fec, which disposes the temp string and
resumes unwinding; the exception path is recorded, not
modelled as a normal return.

NOT modelled: what the produce or emit callees do with their
arguments, what the +0x548 object or the +0x360 sink denote,
or behaviour on dangling pointers. A null object raises,
matching the binary's unconditional read of +0x548.
"""

FORMAT_STRING = "[%s:774] STATISTICS:\n %s"
FILE_STRING = "db/db_impl/db_impl.cc"
EMIT_LEVEL = 1
FIELD_OFFSET = 0x548
EMIT_FIELD_OFFSET = 0x360
VTABLE_SLOT = 0xE8


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


def stats_emit(obj, produce, emit, events):
    """Run the pinned behaviour.

    obj: dict with "ptr_0x548" (opaque/None) and "field_0x360"
    (opaque).
    produce: callable(temp_slot, field_obj) -> TempString.
    emit: callable(level, field_addr, fmt, file, temp_ptr).
    events: list the model appends observable steps to, in order.

    Returns "returned" on every normal path; the event list is
    what distinguishes the paths.
    """
    if obj is None:
        raise ValueError("null object pointer")
    field = obj["ptr_0x548"]
    if field is None:
        events.append("early-return: +0x548 slot null")
        return "returned"
    temp = produce("temp-slot", field)
    events.append("produce called (vtable slot 0xe8)")
    emit(EMIT_LEVEL, "object+0x360", FORMAT_STRING, FILE_STRING,
         temp.pointer)
    events.append("emit called")
    if not temp.inline:
        events.append("delete temp pointer size %d" % (temp.capacity + 1))
    else:
        events.append("temp inline: no free")
    return "returned"
