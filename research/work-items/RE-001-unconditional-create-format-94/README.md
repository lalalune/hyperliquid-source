# RE-001: unconditional create-and-format 0x514e9f0 (node #94)

Task ID: RE-001. Bounded question: what does node #94 function 0x514e9f0
do with its outer argument and destination string — how does its
get-or-create lookup dispatch between returning 0 and formatting a fresh
record, how are the `=` and `; ` separator strings built without a string
constructor, and which callers consume it?

## What is pinned

Function 0x514e9f0..0x514eb3a (330 bytes, FDE 0x00633f5c) takes an outer
object in rdi and a destination string in rsi. It runs the get-or-create
lookup 0x51e9220 unconditionally — there is no view argument and no parser
or index gate, unlike its sibling 0x514eb90 (the indexed create-and-format
item), which gates on a parsed view before calling the same lookup and the
same formatter. The lookup is called with the status slot at rsp+0x10, the
field at [[outer + 0x788] + 0x30] and the shared slot at rsp+0x00 (zeroed
by movaps before the call).

- Status byte at rsp+0x10 nonzero (entry already existed): run the
  cleanup (status array pointer via _ZdaPv when nonzero, shared control
  pointer via 0x4f94a90 when nonzero) and return 0 with the destination
  unchanged.
- Status byte zero (fresh record created): build `=` and `; ` as inline
  stack strings — no call to the string constructor 0x514b6d0, which the
  indexed sibling uses for the same two literals. `=` lives at rsp+0x40
  (pointer rsp+0x50, length 1, byte 0x3d); `; ` lives at rsp+0x20
  (pointer rsp+0x30, length 2, bytes 0x3b 0x20, NUL at rsp+0x32). Format
  the fresh record pointer (first qword of the shared slot) with
  0x5407f00 into a temporary string at rsp+0x60, move-assign it into the
  destination with 0x514b4f0, dispose the temporary, `; ` and `=` in that
  order, run the cleanup, and return 1.

The function is stack-canary protected (canary slot rsp+0x88,
`__stack_chk_fail` on mismatch). Its exception entries are the two landing
stubs at the tail of its own range (0x514eb22 jumping to the control-only
entry 0x514e9b3 of the cleanup routine, 0x514eb2e jumping to the full entry
0x514e994); each stub moves the exception object from rax to rbx first.
The cleanup routine 0x514e994..0x514e9e2 (78 bytes, FDE 0x00633f9c, 14 int3
padding to the window) is cited as the window's exception consumer, not
claimed as a standalone function: its full entry disposes `; `, `=`, the
status array pointer and then the shared control pointer, its control
entry disposes only the control pointer, and it ends with the canary check
and `_Unwind_Resume`. It does not dispose the rsp+0x60 formatter temporary;
that is recorded as observed, not explained.

Caller census: a full .text direct-rel32 scan, a rel32 tail-jump scan and
a whole-file qword scan find no direct caller, tail jump or absolute
pointer for 0x514e9f0, so the reaching path is left unclaimed, exactly as
with the indexed sibling.

## Evidence format

This packet follows the semantic-record format: records.json holds
semantic records only (window, callees, cleanup routine, landing stubs,
censuses, composed rule, unknowns). It holds no per-instruction mnemonic
list. Instruction-level detail lives only in the raw objdump excerpt text
files, which are verbatim whole-function exports produced by
export_excerpts.py (the objdump command for each file is the script
itself). The mnemonics in those files — including `endbr64` at the window
entry and at both landing stubs — are genuine instructions present in the
target binary, not placeholders; verify.py re-checks every excerpt
byte-for-byte against a fresh objdump run on the digest-verified binary.

## Files

- records.json — semantic records (no mnemonic list).
- window.objdump.txt — the whole 330-byte window plus its two landing
  stubs, ending exactly at the next FDE (no padding).
- cleanup.objdump.txt — the shared cleanup routine plus its int3 padding.
- lookup.objdump.txt, formatter.objdump.txt, moveassign.objdump.txt,
  control.objdump.txt — callee excerpts, cited as callees only.
- frames.txt — the six FDE lines for the window, cleanup routine and
  four callees.
- relocations.txt — PLT stub to GOT resolutions, verified from stub bytes.
- verify.py — runnable checker for the records against a node #94 binary.
- export_excerpts.py — regenerates the excerpts from a node #94 binary.

## Target binding

All results bind to the node #94 binary SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
(artifacts/node/94/hl-node; work copy work/hl-node-94.bin on checkouts
where that path is still an LFS pointer).

## Unknowns (kept separate from observations)

- The identity and contents of the outer object, its +0x788 container
  and its +0x30 field.
- The lookup's internal search and creation rules, and the meaning of the
  fresh record's fields to the formatter.
- The formatter's output text for a given record (callee only here).
- The reaching path (no caller, tail jump or absolute pointer exists).
- Why a fresh record is formatted while an already-existing entry
  returns 0 without formatting.
- Which call site each landing stub serves (LSDA mapping, not pinned
  from the window bytes).

## Environment limits (stated honestly)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java. The analysis
above is static objdump/FDE evidence against the digest-verified work
binary plus a Python model and tests; `make verify` / `make test` /
`make catalogue-check` were not run in this environment, and no execution
of the target binary is claimed.
