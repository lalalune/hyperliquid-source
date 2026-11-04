"""Model of node #115 routine 0x5d51d80: conditional record reset.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes two arguments: an object pointer in rdi and a
record pointer in rsi. It proceeds only when BOTH gates pass:

1. the byte at record +0x00 is non-zero (zero returns at once;
   the object flag is never read on this path), and
2. the byte at object +0x333 is zero (non-zero returns at once).

On the proceed path, end to end, in order:

1. Build: call 0x61cfed0 with (stack temp slot, record). The
   callee is opaque here; the model takes it as a caller-supplied
   callable that fills a 32-byte string-shaped temp (pointer at
   +0x00, capacity-or-inline-buffer at +0x10).
2. Emit: call 0x5fcf060 with (2, object +0x360 by address,
   "[%s:755] Ignoring error %s", "db/db_impl/db_impl.cc",
   temp pointer). The callee is opaque; only the argument list
   and order are pinned.
3. Temp disposal, std::string SSO rule: if the temp pointer
   differs from the temp's own +0x10 slot address (heap form),
   delete it with size capacity + 1; inline form frees nothing.
4. Record reset: save the pointer at record +0x08, then write
   zero to record +0x00 (4 bytes), +0x04 (2 bytes) and +0x08
   (8 bytes).
5. If the saved +0x08 pointer was non-null, delete[] it (the
   binary reaches delete[] through a tail jump; the observable
   effect is identical).

The routine never reads the record past +0x0f, never reads any
object offset other than +0x333 (the gate byte) and +0x360
(whose address, not contents, is passed to the emit call), and
writes nothing besides the record reset above. Its landing-pad
entry at 0x5d51e62 jumps to the cleanup block at 0x5d51d54,
which disposes the temp string and resumes unwinding; the
exception path is recorded, not modelled as a normal return.

NOT modelled: what the build or emit callees do with their
arguments, what the object/record denote, or behaviour on
dangling pointers. A null object or record raises, matching the
binary's unconditional dereferences (record +0x00 is read first,
with no null check).
"""

FORMAT_STRING = "[%s:755] Ignoring error %s"
FILE_STRING = "db/db_impl/db_impl.cc"
EMIT_LEVEL = 2
OBJECT_FLAG_OFFSET = 0x333
OBJECT_EMIT_FIELD_OFFSET = 0x360
RECORD_GATE_OFFSET = 0x00
RECORD_POINTER_OFFSET = 0x08


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


def record_reset(obj, record, build, emit, events):
    """Run the pinned behaviour.

    obj: dict with "flag_0x333" (int) and "field_0x360" (opaque).
    record: dict with "byte_0x00" (int) and "ptr_0x08" (opaque/None).
    build: callable(temp_slot, record) -> TempString.
    emit: callable(level, field_addr, fmt, file, temp_ptr).
    events: list the model appends observable steps to, in order.

    Returns "returned" on every normal path; the event list is
    what distinguishes the paths.
    """
    if obj is None or record is None:
        raise ValueError("null object or record pointer")
    if record["byte_0x00"] == 0:
        events.append("early-return: record gate byte zero")
        return "returned"
    events.append("read object flag 0x333")
    if obj["flag_0x333"] != 0:
        events.append("early-return: object flag non-zero")
        return "returned"
    temp = build("temp-slot", record)
    events.append("build called")
    emit(EMIT_LEVEL, "object+0x360", FORMAT_STRING, FILE_STRING,
         temp.pointer)
    events.append("emit called")
    if not temp.inline:
        events.append("delete temp pointer size %d" % (temp.capacity + 1))
    else:
        events.append("temp inline: no free")
    old_pointer = record["ptr_0x08"]
    record["byte_0x00"] = 0
    record["word_0x04"] = 0
    record["ptr_0x08"] = 0
    events.append("record zeroed (+0x00 dword, +0x04 word, +0x08 qword)")
    if old_pointer is not None:
        events.append("delete[] saved +0x08 pointer")
    else:
        events.append("saved +0x08 pointer null: no delete[]")
    return "returned"
