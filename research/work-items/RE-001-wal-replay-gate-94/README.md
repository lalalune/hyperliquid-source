# RE-001: map node #94 WAL replay gate 0x4fa87a0

Task: RE-001 (#94 function map). Bounded question: given an out status
struct and a context struct, what gate sequence does node #94 run
before it hands control to the WAL replay caller 0x520e830 (mapped by
PR #1935), and what does each gate write into the out struct?

- Component: node #94 WAL replay gate, window `0x4fa87a0..0x4fa88de`
  (318 bytes, single FDE 0xf6ceac, cie=0xce1518, no LSDA), plus the
  detail builder `0x542f040..0x542f137` it calls on both report paths.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the gate order,
  the comparison direction, the two report texts and decision bytes,
  the builder's out layout, the replay call's argument forwarding,
  the canary frame, and the four vtable slots; inference for the
  "requested sequence / last written sequence" reading of the counter
  gate (the report text names a not-yet-written sequence and the
  report fires exactly when rdx exceeds the qword, which is the only
  reading consistent with the text); unresolved for the source-level
  meaning of the virtual pre-call's 0x3c argument, the types of the
  context struct and its +0x68 object, and the replay caller's fourth
  and fifth argument roles (see records.json).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- numpy: not needed (the census scans use plain bytes and struct)
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).

## Answer

`replay_gate(out, ctx, requested, b, c)` returns `out`. The phases
below run in order. A status is 16 bytes: decision byte at +0, zero
bytes at +1/+2, a u16 zero at +3, a zero byte at +5, and an owning
message buffer pointer at +8.

1. Optional virtual pre-call: when the pointer at ctx+0x610 is
   non-null, its vtable slot +0xb0 (index 22) is called with
   (object, 0x3c, 1). The return value is ignored, and the call
   happens before either gate, even on paths that then report.
2. Write-prepared gate: when the byte at ctx+0x970 is nonzero, the
   detail builder writes decision 3 and a copy of
   "This API is not yet compatible with write-prepared/
   write-unprepared transactions" (rodata 0x7e56d0, 80 bytes) into
   out, and the function returns out. The replay caller is not
   reached. The builder frees a previous out message first.
3. Written-sequence gate: let limit be the qword at
   (ctx+0x68 field)+0x108. When requested (rdx) is strictly greater
   than limit, the builder writes decision 1 and a copy of
   "Requested sequence not yet written in the db" (rodata 0x7d86c8,
   44 bytes) into out, and the function returns out. The comparison
   is unsigned: `cmp %r12,%rax` followed by `jae` to the replay
   path, so the replay path is taken exactly when limit >= requested.
   The flag gate runs first, so a set flag reports decision 3 even
   when the sequence is also not yet written.
4. Replay delegation: otherwise the WAL replay caller 0x520e830 is
   called with (out, ctx+0x1518, requested, b, c, value of the
   ctx+0x68 field) — the window's own rdx, rcx and r8 forwarded
   unchanged, the replay context taken at ctx+0x1518, and the d
   argument taken from the same ctx+0x68 field the gate dereferences.
   After the call, control flows to the shared canary check and the
   function returns out.

Reachability: no direct call or tail jump to this window exists in
.text. It is reached through virtual dispatch at virtual index 106
(+0x350 from the vtable pointer) in four vtables (first-function
slots 0x5757f50, 0x5759cc8, 0x575a1a8, 0x575a7a8), which share their
first two function entries and diverge later. The window's own frame
carries a stack canary at rsp+0x28, checked on every return path;
the canary-failure stub at 0x4fa88d9 lies inside the FDE range.

## Verification

- `python3 research/work-items/RE-001-wal-replay-gate-94/verify.py`
  prints ALL CHECKS PASSED (binary digest, manifest, excerpt
  regeneration, four byte-for-byte samples, both rodata strings,
  the four relocation slots, and the census reproduction).
- `python3 -m unittest tests.test_wal_replay_gate -v` (pytest is not
  installed on this VM, so the unittest-style tests are run with the
  unittest runner; the file is also pytest-runnable).
