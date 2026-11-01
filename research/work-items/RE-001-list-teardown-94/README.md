# RE-001: bind node #94 list teardown 0x514bd40 with its array clear

Task: RE-001. Bounded question: what does the whole function at
0x514bd40 do to its object — which list it walks, what it frees per
node, and how it then clears and conditionally frees the object's
array?

## Answer (from the bytes)

The function is one teardown routine with two phases, both acting on
the same object (rdi, preserved in r12):

**Phase 1 — list walk** (0x514bd40..0x514bd92). The list head is
`[object + 0x10]`. A null head jumps straight to phase 2. Otherwise,
per node, in this exact order:

1. Save the next pointer from `[node + 0x0]` (rbp) *before* any free.
2. Dispose the string stored at `node + 0x8`: if the pointer at
   `[node + 0x8]` equals `node + 0x18` (the address of the capacity
   field), the string is inline and no buffer delete runs; otherwise
   call operator delete with (buffer = `[node + 0x8]`,
   size = `[node + 0x18] + 1`).
3. Call operator delete with (node, size 0x78).
4. Advance to the saved next pointer; stop when it is null.

**Phase 2 — array clear** (0x514bd92..0x514bde5). Then:

1. `memset([object + 0x0], 0, [object + 0x8] * 8)`.
2. Zero `[object + 0x10]` and `[object + 0x18]`.
3. If `[object + 0x0]` equals `object + 0x30`, the array storage is
   inline and the function returns; otherwise it tail-calls operator
   delete with (`[object + 0x0]`, `[object + 0x8] * 8`).

The function returns void. The three callee-saved registers (r12,
rbp, rbx) are pushed and popped in balance on both exit paths.

## Evidence

- Target: node #94 binary, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (91,774,280 bytes), bound in `records.json` and checked by
  `verify.py`.
- Function: 0x514bd40..0x514bde5 (165 bytes, FDE section offset
  0x0029a714), 11 int3 padding bytes to the next FDE at 0x514bdf0.
- PLT stubs: operator delete at 0x5660440 (GOT slot 0x5778f48,
  `R_X86_64_JUMP_SLOT _ZdlPvm`), memset at 0x5660140 (GOT slot
  0x5778dc8, `R_X86_64_JUMP_SLOT memset`). The GOT slots' file bytes
  are the stubs' own lazy-binding resolver entries (0x5660446 and
  0x5660146), not the resolved symbols.
- Caller census: a full `.text` disassembly scan finds **no** direct
  call and **no** tail jump to 0x514bd40. No caller is invented; the
  function is pinned by its own bytes, its FDE, and its PLT records.
- The `endbr64` at 0x514bd40 is a genuine instruction in the target
  binary, not a placeholder. The `cs nopw` at 0x514bd56 and the
  `nopl` at 0x514bddc are genuine alignment padding.

## Observations vs inferences

- Observed: every branch/call target above, re-derived from the raw
  encodings by `verify.py`; the per-node field offsets; the
  capacity+1 delete size; the count*8 memset/delete sizes; the
  object+0x30 comparison.
- Inference (stated, not established): the three qwords at
  node+0x8/+0x10/+0x18 behave exactly like a `std::string` — pointer,
  length, capacity-or-inline-buffer. The SSO test compares the pointer
  against the address of the capacity field, and the heap delete size
  is capacity+1, the allocation size of a NUL-terminated buffer. The
  model therefore calls it a string buffer; the length field at
  node+0x10 is never read by this function.
- Not claimed: any role for the qword at object+0x18 beyond being
  zeroed in phase 2; any source-level name for the object, the list,
  or the array; any meaning for node bytes beyond +0x28 (never read);
  objdump's nearest-symbol annotations.
- Distinguished, not re-claimed: the recursive destructor of
  RE-001-recursive-destructor-94 (#1327) deletes one list recursively
  and is a different routine; the counted-ptr dispose of
  RE-001-counted-ptr-dispose-94 (#1339) is a vtable dispatch; the
  preceding field-sum function 0x514bcd0 (#1349) shares only adjacency
  (this is its following FDE). The following FDE at 0x514bdf0 is not
  examined here.

## Files

- `window.objdump.txt` — the whole function plus its int3 padding,
  verbatim objdump output.
- `plt.objdump.txt` — both PLT stubs verbatim.
- `frames.txt` — the function's FDE line.
- `relocations.txt` — the two GOT relocation records.
- `records.json` — semantic records only (no per-instruction list).
- `verify.py` — checks the records against a node #94 binary.
- `export_excerpts.py` — regenerates the excerpts byte-identically.

## Commands

```
objdump -d --start-address=0x514bd40 --stop-address=0x514bdf0 work/hl-node-94.bin
objdump -d --start-address=0x5660140 --stop-address=0x5660150 work/hl-node-94.bin
objdump -d --start-address=0x5660440 --stop-address=0x5660450 work/hl-node-94.bin
python3 research/work-items/RE-001-list-teardown-94/verify.py --binary work/hl-node-94.bin
```

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so
`make doctor` fails and `make catalogue-check` fails on the
pre-existing LFS-pointer identity of `artifacts/node/94/hl-node`.
Those failures are pre-existing and are not regressions from this
packet; the packet's own verifiers run against the digest-verified
work copy `work/hl-node-94.bin` and pass.
