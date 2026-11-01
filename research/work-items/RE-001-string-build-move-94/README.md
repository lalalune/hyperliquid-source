# RE-001: string build-and-move over node #94 (0x514bdf0)

Task ID: RE-001. Bounded question: what does the 133-byte function at
0x514bdf0 in node #94 do with its second argument, and what happens
to the temporary string it builds on the stack? Answer: it asks the
shared producer callee 0x51cd470 to fill a stack temporary string
from the container sub-object at [chain + 0x30] (with flags 1, 1),
move-assigns that temporary into the caller's out string with the
already-bound move-assign 0x514b4f0, destroys the temporary (freeing
its heap buffer, if any, with size capacity + 1), and always returns
1. The out string ends up exactly equal to the string the producer
built; the old out storage is freed through the destroyed temporary,
not leaked.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514bdf0..0x514be75, 133 bytes, FDE at .eh_frame+0x0029a74c
  (length 0x28), no int3 padding — the next FDE starts exactly at
  0x514be75.
- Stack canary: the value at %fs:0x28 is stored at rsp + 0x28 on entry
  and checked before the return; a mismatch calls __stack_chk_fail
  (PLT stub 0x5660430) instead of returning.
- Two callee-saved registers are pushed and popped in balance (rbp,
  rbx); the frame is 0x38 bytes.

## Observations (read from the bytes)

- Arguments: rdi = input object, rsi = out string pointer (saved in
  rbx before anything else uses rsi).
- Container chain: rax = [rdi + 0x788]; the producer's second
  argument is rsi = [rax + 0x30]. The +0x788 link is the same chain
  head the neighbouring range/field-sum functions use; the +0x30
  sub-object's type is not claimed. No source-level type name is
  claimed for any link.
- Producer call (site 0x514be28): rdi = rsp (the stack temporary),
  rsi = [chain + 0x30], edx = 1, ecx = 1 (both set before the pushes
  at 0x514bdf5/0x514bdfa). The callee's return value in rax is never
  read afterwards: the next instructions move rbx to rdi and rsp to
  rsi for the move-assign. The flags' meanings are not claimed.
- Producer callee 0x51cd470 (own FDE at .eh_frame+0x006392e0, length
  0x50, 4075 bytes, 5 int3 padding bytes to the next FDE at
  0x51ce460): its prologue initializes the string at its first
  argument to empty (pointer = out + 0x10, byte 0 at out + 0x10,
  length 0 at out + 0x8) and an _M_append PLT call at 0x51cd506 is
  observed in the excerpt. Its full contents are a separate work
  item and are NOT claimed here — this packet claims the entry's
  build-move-dispose behavior, with the producer treated as the
  string source whose output the entry moves. The whole callee
  disassembly is nevertheless shipped verbatim in callee.objdump.txt
  so the claim's boundary is checkable.
- Move-assign call (site 0x514be33): rdi = rbx (out), rsi = rbp
  (= rsp, the temporary), target 0x514b4f0 — the move-assign bound
  by the merged #1321 packet, whose semantics are reused here, not
  re-claimed. After it, out holds the produced string and the
  temporary holds the old out storage.
- Temporary disposal: rdi = [rsp] (temporary pointer), rax =
  rsp + 0x10; if equal (je at 0x514be44 to 0x514be54) nothing is
  freed — that is the inline/SSO case, where the pointer is the
  temporary's own buffer address. Otherwise rax = [rsp + 0x10]
  (capacity), rsi = rax + 1, and operator delete is called via the
  _ZdlPvm PLT stub 0x5660440 (site 0x514be4f). The +1 is the
  capacity-plus-terminator size of the string-destroy convention.
  Temporary layout: pointer at rsp + 0x0, length at rsp + 0x8,
  capacity-or-inline-buffer at rsp + 0x10.
- Epilogue: canary reloaded and compared (jne at 0x514be62 to the
  __stack_chk_fail call at 0x514be70), stack restored, eax = 1,
  rbx/rbp popped, ret. The return value is 1 on every returning
  path; a canary mismatch never returns.
- Direct-caller census (full .text byte scan for e8 rel32 calls and
  e9 rel32 jumps to 0x514bdf0): NO direct callers and NO tail jumps.
  It is bound here as a complete behavior — a whole function plus
  its producer call, its move-assign and its disposal arm — not as a
  lone window fragment, and no caller is invented for it.
- Producer census (same scan for 0x51cd470): exactly 3 direct sites
  — 0x504cdc1, 0x504d736, 0x514be28 (this entry). The other two sites
  are census only; both were verified as genuine call instructions
  by local disassembly windows, and both pass flags edx = 0,
  ecx = 0, unlike this entry's 1, 1.

## Inferences (labelled, not observations)

- The +0x788/+0x30 chain is read as one container object holding the
  producer's source sub-object; the intermediate objects' types are
  not claimed.
- The temporary's pointer/capacity fields are read with the
  standard string layout (pointer, length, capacity-or-inline-buffer),
  which the disposal test (pointer == own + 0x10) and the
  capacity + 1 delete size both confirm in the bytes.
- The producer is read as a string source: it initializes an empty
  string at its first argument and appends to it. What string it
  produces for a given source is the producer's own future work
  item, not claimed here; the model takes the produced string as an
  input, exactly as the entry receives it from the callee.

## Unknowns (not claimed)

- How the entry is reached (no direct caller exists): virtual or
  indirect dispatch is possible but not demonstrated, so no dispatch
  mechanism is claimed.
- The producer's output for any particular source, the meaning of
  its two flag arguments, and the source-level types of the
  container, the out string's owner, and the producer's source are
  not claimed.
- The other two producer call sites' enclosing functions are not
  modelled; only their addresses and flag values are recorded.

## Overlap notes (checked before building)

- No work item, tool, test, or doc in the tree claims 0x514bdf0's
  behavior, and no open WalkCrypto PR covers this function. The
  only in-tree mentions of 0x514bdf0 before this packet are a
  caller-site line in the merged #1321 packet (this entry is one of
  move-assign's 20 callers) and a next-FDE citation in the open
  #1353 packet — neither claims this entry. The only in-tree
  mentions of 0x51cd470 are call-site lines inside other packets'
  disassembly excerpts, not claims on this item.
- Neighbours are distinct and not re-claimed: 0x514bd40 (list
  teardown, open PR #1353, preceding function) and the following
  FDE at 0x514be75 (unexamined, different function).

## Evidence format

- records.json holds semantic records only (carve ranges with SHA-256,
  branch site-to-target pairs, call sites, container-chain offsets,
  caller/callee censuses, the composed rule). It contains no
  per-instruction list.
- Instruction-level detail lives only in the raw objdump excerpts,
  kept whole-function: window.objdump.txt (0x514bdf0..0x514be75,
  the whole function, no padding) and callee.objdump.txt
  (0x51cd470..0x51ce460, the whole callee plus its 5 int3 padding
  bytes). Regenerate them with export_excerpts.py (same binutils
  2.42).
- verify.py (in this packet) and tools/foundation_string_build_move.py
  (check_packet) are the runnable checkers behind "ALL CHECKS PASSED".
- The endbr64 at 0x514bdf0 and the endbr64 at 0x51cd470 are genuine
  instructions in the target binary, not placeholders; the int3
  bytes after the callee are genuine padding.

## Reproduction

```
objdump -d --start-address=0x514bdf0 --stop-address=0x514be75 work/hl-node-94.bin
python3 research/work-items/RE-001-string-build-move-94/verify.py --binary work/hl-node-94.bin
python3 tests/test_foundation_string_build_move.py
```

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs, no Ghidra/Java, so `make doctor` fails and the repo-wide
`make catalogue-check` is not re-run here (its pre-existing LFS-pointer
identity failure is unrelated to this change); the checks above run
against the digest-verified work binary, not the LFS pointer.
