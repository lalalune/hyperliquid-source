# RE-001: bind node #94's string-plus-block copy 0x514de00 with its 61 call sites

Task ID: RE-001. Bounded question: given a destination object, a source
string object and a 72-byte block, what does the 231-byte function at
0x514de00 build, and where is it used? Answer: it builds a 0x68-byte
object whose first member is a deep copy of the source string and
whose remaining 72 bytes are a verbatim copy of the block; it is used
61 times, all inside the single enclosing function 0x515b750, whose
sampled call sites zero a stack block, store one code pointer at
block+0x8, and pass a string-layout object as the second argument.

This is a whole complete behavior, not a fragment: the entry window
plus its SSO and heap string arms plus its _M_create and memcpy
callees plus the 72-byte block copy plus the stack-canary path plus
all 61 direct call sites end to end.

This window was used before only as the next-FDE pointer after the
level-index-sum formatter (0x514dce0 item), which never modelled this
function's body, its string arms, its block copy or its callers.
Nothing here redoes that item's ground; the formatter functions that
appear as block+0x8 values at sampled sites (0x514cc10, 0x514c580)
are cited as values only, not re-modelled.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Window function: 0x514de00..0x514dee7, 231 bytes, FDE at .eh_frame
  +0x0029abcc (length 0x38), 9 int3 padding bytes to the next FDE at
  0x514def0. It starts with endbr64, a genuine instruction present in
  the target binary, not a placeholder. Instruction-level detail lives
  only in the raw excerpt files below; records.json carries semantic
  records, not a per-instruction list.
- Stack canary: fs:0x28 saved at rsp+0x8, __stack_chk_fail@plt
  0x5660430 (GOT 0x5778f40) on mismatch.
- Destination layout: string member at +0x00 (pointer +0x0, length
  +0x8, union +0x10), copied block at +0x20..+0x68 (72 bytes).
- Source layout: pointer at +0x0, length at +0x8; the union at +0x10
  is never read, so SSO and heap sources copy identically.

## Observations (read from the bytes)

- Arguments: rdi = destination object (saved in rbx), rsi = source
  string object, rdx = 72-byte block (saved in rbp). The destination's
  pointer slot is first set to its own SSO buffer (dest+0x10); the
  heap arm overwrites it, the SSO arms keep it.
- Length arms, on the unsigned length at [rsi+0x8]:
  - length 0: no memcpy, no _M_create; length 0 stored at dest+0x8,
    NUL byte at dest+0x10.
  - length 1: the single byte is moved directly into dest+0x10 (no
    memcpy call); length 1 stored, NUL byte at dest+0x11.
  - lengths 2..15: memcpy(dest+0x10, source pointer, length) via
    memcpy@plt 0x5660100 (GOT 0x5778da8) at 0x514ded1; length stored,
    NUL byte at dest+0x10+length.
  - length > 15: _M_create@plt 0x56604d0 (GOT 0x5778f90) at
    0x514deb8 with rdi = destination string, rsi = rsp (the capacity
    slot, initialized to the source length), rdx = 0; the returned
    buffer is stored at dest+0x0, the slot value at dest+0x10, then
    memcpy into the buffer, then length stored at dest+0x8 and a NUL
    byte at buffer+length. In this call shape (old capacity 0) the
    same slot value feeds both the union and the length stores, so
    the model records the heap capacity slot as the source length;
    any _M_create growth rule beyond that is left as an unknown.
- Block copy: four 16-byte unaligned moves (block+0x00/+0x10/+0x20/
  +0x30 to dest+0x20/+0x30/+0x40/+0x50) plus one 8-byte move
  (block+0x40 to dest+0x60). No byte of the block is interpreted.
- The function returns no value.
- Callers: exactly 61 direct e8 sites, all inside the enclosing
  function 0x515b750..0x515f78b (FDE at .eh_frame +0x00634d78, length
  0x34, SHA 3e4b07c4...; cited as consumer only). The census was
  confirmed instruction-by-instruction against an objdump
  disassembly of that range; a full .text e9 scan found no tail jump
  and a whole-file qword scan found no vtable reference to
  0x514de00. Sampled setups (caller_sample.objdump.txt covers the
  first three): the block is zeroed, one code pointer is stored at
  block+0x8 (0x514b390, 0x514cc10, 0x514c580 in the sample; 0x514bdf0
  and 0x514e030 at two further sampled sites), and the second
  argument is a string-layout object (a .bss object at four sampled
  sites, register r15 at one). The full 61-site list is in
  records.json.
- Unknowns: the wider semantics of the 0x68-byte object and the block
  beyond the verbatim copy; what the block+0x8 code pointer means to
  the consumer; the enclosing function's overall purpose; the
  _M_create capacity rule beyond the observed slot behavior; the
  contents of the .bss string objects passed at sampled sites.

## Excerpt commands

Run from the repository root:

    objdump -d --start-address=0x514de00 --stop-address=0x514def0 work/hl-node-94.bin
    objdump -d --start-address=0x515dbc8 --stop-address=0x515dcb9 work/hl-node-94.bin
    objdump -d --start-address=0x5660100 --stop-address=0x5660110 work/hl-node-94.bin
    objdump -d --start-address=0x5660430 --stop-address=0x5660440 work/hl-node-94.bin
    objdump -d --start-address=0x56604d0 --stop-address=0x56604e0 work/hl-node-94.bin

or run `python3 export_excerpts.py` in this directory to regenerate
them. The window excerpt runs to the next FDE start (0x514def0), so
it includes the 9 int3 padding bytes after the window's FDE end
(0x514dee7). The caller sample is a contiguous sample of the
enclosing function covering its first three call sites, starting at
the site-1 code-pointer lea (0x515dbc8); the full census is in
records.json.
