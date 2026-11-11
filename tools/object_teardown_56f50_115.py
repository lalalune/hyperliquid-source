"""Python model of node #115 routine 0x5d56f50 (RE-001 object teardown).

The routine takes an object in rdi and tears down its members in a
fixed order, but never frees the object itself, never reads a vtable
slot, and performs no canary check. It pushes r15/r14/r13/r12/rbp/rbx
and reserves 8 bytes of stack.

String rule (everywhere below): a string is (text, heap_capacity or
None); None means short form (data pointer equals the string address
+ 0x10), which frees nothing, otherwise a sized delete of (pointer,
capacity + 1).

Buffer rules: a reset-capable buffer is {"begin": bool,
"end_differs": bool, "size": int} -- when end differs from begin the
end is first reset to begin, then the buffer is freed with its size
when begin is non-null. A free-only buffer is {"begin": bool,
"size": int} -- freed with its size when begin is non-null, with no
end reset.

Phases, in order:
 1. +0x1f0 pointer: if non-null, call 0x5f3c850 with it, then a sized
    delete of 0x10 (call-shape only for the callee).
 2. +0x148 flag: zeroed when nonzero.
 3. +0x198 buffer (reset-capable; capacity end +0x1a8).
 4. Record loop over [+0x130, +0x138) with stride 0x218; per record:
    +0x210 pointer: if non-null, call 0x5d8d820 with it, then a sized
    delete of 0x290; the count at +0x68 walks a string array at +0x1f0
    in reverse (stride 0x30), disposing each string and ending at 0;
    the string vector at +0x1f8/+0x200 is disposed forward (stride
    0x30), its end reset to begin when non-empty, and its buffer freed
    (capacity end +0x208); the +0x00 flag is zeroed when nonzero; the +0x50 buffer
    is reset-capable (capacity end +0x60). The record pointer is
    advanced to the next record before the +0x50 buffer free.
    A second loop over the same +0x1f8 range is present in the code
    but unreachable: its entry test compares the reloaded begin
    against the same begin value, so it always jumps to the buffer
    free; the model emits no operations for it.
 5. Record array: the +0x130 buffer freed (capacity end +0x140).
 6. +0xc8 flag: zeroed when nonzero.
 7. +0x118 buffer (reset-capable; capacity end +0x128).
 8. Call 0x5d35c30 with object+0xb0 (call-shape only).
 9. +0x98 buffer, then +0x80 buffer (free-only).
10. String vector at +0x68/+0x70 (stride 0x28; string at element
    +0x08, short-form address element +0x18), then its buffer freed
    (capacity end +0x78).
11. +0x50 buffer (free-only).
12. Element loop at +0x38/+0x40 (stride 0x40): per element, the
    +0x38 pointer, when non-null, is passed to 0x5d350c0
    (call-shape only), then the +0x08 string is disposed; then the
    buffer is freed (capacity end +0x48).
13. Element loop at +0x08/+0x10 (stride 0x40): per element, the +0x20
    string then the +0x00 string are disposed; then the buffer is
    freed (capacity end +0x18) via a tail jump to the sized-delete
    PLT, or the routine returns plainly when the buffer is null.

The +0x1f0 string array inside each record is not freed by this
routine: its strings are disposed and its count cleared, but no sized
delete of the array buffer appears in the routine.

Records are dicts: {"elem_210": id or None,
"count_strings": [string], "strvec": [string],
"strvec_buf": free-only buffer, "flag_00": bool,
"buf_50": reset-capable buffer}. Objects are dicts with the keys used
by teardown(); teardown returns the operation list.
"""

ENTRY_CALL = 0x5F3C850
ENTRY_SIZE = 0x10
RECORD_CALL = 0x5D8D820
RECORD_ELEM_SIZE = 0x290
MEMBER_CALL = 0x5D35C30
ELEM_CALL = 0x5D350C0
RECORD_STRIDE = 0x218


def _dispose_string(owner, string, ops):
    text, heap_cap = string
    if heap_cap is None:
        ops.append(("dispose_string", owner, "short"))
    else:
        ops.append(("dispose_string", owner, "sized", heap_cap + 1))


def _reset_buffer(field, buf, ops):
    if buf["end_differs"]:
        ops.append(("reset_end", field))
    if buf["begin"]:
        ops.append(("free_buffer", field, buf["size"]))


def _free_buffer(field, buf, ops):
    if buf["begin"]:
        ops.append(("free_buffer", field, buf["size"]))


def _teardown_record(record, index, ops):
    elem = record["elem_210"]
    if elem is not None:
        ops.append(("member_call", f"record{index}+0x210", RECORD_CALL))
        ops.append(("free", f"record{index}+0x210", RECORD_ELEM_SIZE))
    for i, string in enumerate(reversed(record["count_strings"])):
        _dispose_string(f"record{index}+0x1f0[{i}]", string, ops)
    ops.append(("clear_count", f"record{index}+0x68"))
    for i, string in enumerate(record["strvec"]):
        _dispose_string(f"record{index}+0x1f8[{i}]", string, ops)
    if record["strvec"]:
        # An empty vector jumps straight to the buffer free, so the
        # end reset only happens after a non-empty dispose pass.
        ops.append(("reset_end", f"record{index}+0x200"))
    _free_buffer(f"record{index}+0x1f8", record["strvec_buf"], ops)
    if record["flag_00"]:
        ops.append(("clear_flag", f"record{index}+0x00"))
    _reset_buffer(f"record{index}+0x50", record["buf_50"], ops)


def teardown(obj):
    """Tear down `obj` per routine 0x5d56f50; return the operation list."""
    ops = []
    if obj["ptr_1f0"] is not None:
        ops.append(("member_call", "obj+0x1f0", ENTRY_CALL))
        ops.append(("free", "obj+0x1f0", ENTRY_SIZE))
    if obj["flag_148"]:
        ops.append(("clear_flag", "obj+0x148"))
    _reset_buffer("obj+0x198", obj["buf_198"], ops)
    for i, record in enumerate(obj["records"]):
        _teardown_record(record, i, ops)
    _free_buffer("obj+0x130", obj["record_array"], ops)
    if obj["flag_c8"]:
        ops.append(("clear_flag", "obj+0xc8"))
    _reset_buffer("obj+0x118", obj["buf_118"], ops)
    ops.append(("member_call", "obj+0xb0", MEMBER_CALL))
    _free_buffer("obj+0x98", obj["buf_98"], ops)
    _free_buffer("obj+0x80", obj["buf_80"], ops)
    for i, string in enumerate(obj["strvec_68"]):
        _dispose_string(f"obj+0x68[{i}]", string, ops)
    _free_buffer("obj+0x68", obj["buf_68"], ops)
    _free_buffer("obj+0x50", obj["buf_50"], ops)
    for i, (member, string) in enumerate(obj["elems_38"]):
        if member is not None:
            ops.append(("member_call", f"obj+0x38[{i}]+0x38", ELEM_CALL))
        _dispose_string(f"obj+0x38[{i}]", string, ops)
    _free_buffer("obj+0x38", obj["buf_38"], ops)
    for i, (string_b, string_a) in enumerate(obj["elems_08"]):
        _dispose_string(f"obj+0x08[{i}]+0x20", string_b, ops)
        _dispose_string(f"obj+0x08[{i}]+0x00", string_a, ops)
    if obj["buf_08"]["begin"]:
        ops.append(("tail_free_buffer", "obj+0x08", obj["buf_08"]["size"]))
    else:
        ops.append(("plain_return",))
    return ops
