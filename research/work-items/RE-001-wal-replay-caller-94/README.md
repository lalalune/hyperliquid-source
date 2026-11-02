# RE-001: map node #94 WAL replay gate-and-replace caller 0x520e830

Task: RE-001 (#94 function map). Bounded question: given a caller out
status struct, a context struct and four opaque arguments, what exact
sequence of gate, replay, helper-status and object-replacement steps
does node #94's caller of the WAL replay orchestrator run, and what
does it write into the out struct and the replaced object slot?

- Component: node #94 WAL replay caller, window
  `0x520e830..0x520eb1c` (748 bytes, single FDE 0x131d424,
  cie=0x1301ae8, lsda=0xbdce41), plus its exception cleanup function
  `0x520e7e4..0x520e830` (76 bytes, FDE 0x131d460).
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the gate, the
  status layout and its copy/move rules, the orchestrator and helper
  call arguments, the constructor call arguments and its prologue
  stores, the object replacement, both heap-vector teardown sites,
  the virtual finish call, the cleanup entries and landing stubs,
  and the sole direct caller; inference for the "WAL replay
  gate-and-replace caller" reading (the orchestrator identity is
  pinned by PR #1932's packet; source-level names are not), for the
  dead second delete check in the move sequence, and for the
  constructor's field mapping beyond its prologue; unresolved for
  the source-level reason the gate code is exactly 3, the internals
  of every callee and virtual call, the ctx fields' and arguments'
  types, and the LSDA mapping of the landing stubs (see records.json).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- numpy: 1.26.4 (census scans only)
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).

## Answer

`replay_caller(out, ctx, a, b_slot, c, d)` returns `out`. The phases
below run in order. A status is 16 bytes: u32 code at +0, u16 flags
at +4, owning message pointer at +8; only the code's low byte is
ever tested.

1. Gate: if the byte at ctx+0x140 is nonzero, out is set to code 3,
   flags 0, message null, and the function returns. No allocation
   and no callee call happen on this path, and a pre-existing out
   message is not freed, so the caller must pass an empty out.
2. Heap vector: operator new allocates 0x18 bytes, all zeroed, an
   empty vector kept in r12 and in the -0x68 slot.
3. Orchestrator replay: 0x520e1b0 is called with (status1 at -0x60,
   ctx, heap vector).
4. Nonzero orchestrator status: if status1 byte 0 is nonzero,
   status1 is copied into out (code bytes +0..+5 and the message
   pointer; the source stays intact, the old out message is not
   freed), the heap vector is torn down, and the function returns.
5. Helper call: 0x520a260 is called with (status2 at -0x50, ctx,
   heap vector, a).
6. Status move: status2 is moved into status1 — the old status1
   message is freed with delete[] when non-null, then status2's
   code, flags and message are stored into status1 and status2 is
   zeroed. A second delete[] check then reads the already-zeroed
   status2 message slot and never fires on a consistent move.
7. Nonzero helper status: if the new status1 byte 0 is nonzero,
   status1 is copied into out exactly as in phase 4, the heap
   vector is torn down, and the function returns.
8. Object construction: operator new allocates 0xd0 bytes into r12;
   the -0x68 heap-vector slot is cleared and the heap-vector pointer
   is stashed in the dead -0x50 slot; constructor callee 0x52144c0
   is called with (new object, ctx, heap vector, c, ctx+0x08, a)
   in registers and (pointer to the -0x50 slot, d, ctx+0x140 flag
   byte, ctx+0x158 by address) on the stack. Its prologue stores
   0x575bee0 at +0x00, ctx at +0x08, the heap vector at +0x10, the
   first byte read through c at +0x18, ctx+0x08 at +0x20, a at
   +0x28, and the slot's content (the heap-vector pointer) at +0x30.
9. Object replacement: the old object at *b_slot is loaded; when
   non-null, its +0x8 virtual call runs; then *b_slot is set to
   the new object.
10. Heap-vector teardown (stash): the heap vector found through the
    -0x50 stash is torn down — each non-null element gets its +0x8
    virtual call, the array is freed with sized delete when its
    begin pointer is non-null, and the 0x18-byte struct is freed.
    The teardown in phases 4 and 7 is the same shape, with the
    holder in r12 instead of the stash.
11. Virtual finish: the new object at *b_slot is loaded and its
    +0x20 virtual call runs with (out, object); this call is the
    final writer of out on this path, and its internals are not
    pinned here.
12. Final free and return: the status1 message is freed with
    delete[] when non-null (it is not transferred to out on this
    path); the function returns out through the canary check.

Cleanup function 0x520e7e4 (entered from the three landing stubs
inside the window range, which save the exception object into rbx;
the LSDA mapping of stub to protected region is not claimed):
destroy the heap vector through helper 0x520a900 using the value
at -0x88 (the address of the -0x50 slot), free the 0xd0-byte object
in r12 with sized delete, free the status1 message when non-null,
destroy the heap vector through helper 0x520a900 using lea -0x68,
then canary-check and _Unwind_Resume.

Sole direct caller (census only): site 0x4fa88cf in function
0x4fa87a0..0x4fa88de, passing (out=rbp, ctx=rbx+0x1518, a=r12,
b=r13, c=r14, d=rbx+0x68). No tail jumps, no qword references.

## Files

- `records.json` — semantic records only (no per-instruction lists).
- `window.txt`, `cleanup.txt`, `caller-sites.txt` — verbatim
  objdump excerpts, regenerated by `export_excerpts.py`.
- `frames.txt` — verbatim FDE rows for the window, the cleanup
  function, the caller function and the callees.
- `relocations.txt` — the PLT symbols called from the window and
  cleanup; no RELATIVE value is read by either range.
- `verify.py`, `export_excerpts.py`, `census.py` — the packet
  checker, the excerpt regenerator and the census reproducer.
- `MANIFEST.sha256` — SHA-256 of every packet file.
