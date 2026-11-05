# RE-005 node115: the error-value vtable at 0x64005f0

## Question

PR #3012 pinned the three statics before the dispatcher
vtable table and recorded, as context only, the error-value
vtable at 0x64005f0 -- {drop = 0x15be1a0, size 8, align 8,
method = 0x5ca5610} -- lea'd into rcx by the spawn supervisor
(0x15d5b00) on its "failed to spawn thread" panic path. What
is this vtable, what references it, what does its method do,
which bodies produce the values it tags, and where do those
values flow? How does it mesh with the three-result
convention of the write body (0x1533d60) of PR #3012 -- 0,
(errno << 32) | 2, and a static cell's bare address?

## Findings

**It is the one-method trait-object vtable for the 8-byte
tagged io error value, and its method is the value's Debug
format function.** The drop entry is the tag-dispatch drop
glue 0x15be1a0 (PR #3012's error_drop): the stored word's
low two bits select the representation -- 0 = pointer to a
static message datum, 1 = tagged pointer to a 0x18-byte
custom-error box (dropped through the box's own vtable, then
deallocated at 0x18 bytes), 2 = OS error (errno in the high
dword, nothing to free), 3 = bare kind (high dword, nothing
to free). The method cell names a 6-byte PLT stub
(0x5ca5610, `jmp *0x64e1878`) whose GOT slot resolves by
RELATIVE relocation to a 1,237-byte body at 0x5ca7ea0. That
body takes (rdi = pointer to the 8-byte value, rsi = &mut
Formatter) -- the fmt-method convention -- dispatches on
tag & 3 through the jump table at 0x948c90, and renders the
std debug-struct forms: tag 0 opens the struct named
"Error" over the static datum (message &str at +0x00, kind
dword at +0x10 -- exactly the 0x6400488 layout of PR #3012),
tag 1 untags the box pointer and renders "Custom", tag 2
renders "Os" with the high-dword errno, tag 3 renders the
bare kind via the name table at 0x94a778; the "kind" and
"message" field names are written through the debug
machinery, every arm writes through the formatter's
write_str slot (+0x18), and the common exit masks the
result byte with 1 (the fmt::Result tag). No symbol names
any of this; the identity is the byte evidence above.

**Exactly one reference exists.** A binary-wide census
(rip-relative scan of .text, movabs scan, relocation-addend
scan, raw-qword scan of allocated data sections) finds a
single lea, at 0x15d5c42 inside the spawn supervisor, into
rcx as the fourth argument of the panic call. Exactly two
relocations land in the vtable (+0x00 drop, +0x18 method);
size and align are the literal file values 8 and 8; the
vtable lies in .data.rel.ro inside PT_GNU_RELRO. The
method stub is shared: 32 vtables in .data.rel.ro name it
at +0x18, all size 8 / align 8 with 30 distinct
drop bodies of the same tag-dispatch shape between them, and one .got cell
(0x64e0170) holds it as a plain function pointer. This
vtable is the only one whose drop cell names 0x15be1a0.

**Flow.** The spawn sibling 0x15b7a80 (entry 3 of PR
#3000's table) writes its result to the supervisor's stack:
word 0 = success handle, word 1 ([rsp+8]) = the error word.
On success the error word is never read. On failure the
supervisor stores the error word back to (rsp) at
0x15d5c37 and calls the panic-message thunk 0x1680c30
(slot 0x64df6a0) with rdi/rsi = the "failed to spawn
thread" &str, rdx = rsp (pointer to the value), rcx = this
vtable, r8 = the Location 0x64004b8 (PR #3012). The thunk
saves the (value pointer, vtable) pair on its stack, builds
two fmt arguments -- message with formatter function
0x1687590, value pair with formatter function 0x1687260 --
and calls the panic formatting entry through slot
0x64df6b8. The 16-byte adapter at 0x1687260 loads the pair
and tail-calls the vtable's +0x18 method with (value
pointer, formatter): the Debug body above is what renders
the error inside the panic message. If unwinding passes
through the supervisor instead, its cleanup pad at
0x15d5c8f drops the stack error value by a direct call to
0x15be1a0 -- the drop body this vtable names. Seven bodies
call that drop body directly (7 sites), the write body and
the supervisor among them.

**Mesh with the write body.** The write body 0x1533d60
(PR #3012) produces values of this exact encoding: 0 on
success (not an error value), (errno << 32) | 2 for an OS
error (tag 2), and the bare address of the static message
datum 0x6400488 when write(2) returns 0 (tag 0); its EINTR
path drops a value of this type via 0x15be1a0. The
vtable's method reads the same three tags, and its tag-0
arm dereferences statics of the 0x6400488 layout. The
write body never references the vtable; the connection is
the shared encoding and the shared drop body.

## Evidence

9 bodies pinned by FDE extent and sha256;
`tools/error_vtable.py` re-derives every pin, the vtable
decode, the method resolution, both censuses, the jump
table and the string records from the materialized
artifact, and `tests/test_error_vtable.py` passes with no
skips. The error_drop, write_body, spawn_supervisor and
panic_msg_thunk hashes match PR #3012 / PR #3000 exactly;
no pin of either is contradicted.

## Limitations

No symbol names the vtable, the method body or the value
type; the Debug identity rests on the pinned byte evidence
(formatter argument, debug-struct names, field names, the
shared tag dispatch), not on symbol metadata. The other
31 vtables sharing the method stub are recorded by base,
drop target, size and align only; which concrete values
each tags is out of scope. The five direct drop callers
outside the write body and the supervisor are recorded by
site and body only. The spawn sibling result layout is
described from the supervisor's reads of its own stack
frame. The source-level name of the write body's
monomorphised std routine remains unpinned, as in
PR #3012.
