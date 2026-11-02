# RE-001: map node #94 global member replace with its guard, member build, wrapper swap and old-wrapper destruction (0x5169da0)

Task: RE-001 (#94 function map). Bounded question: how does node #94
replace the global member — when it refuses, what fresh member it
builds, what wrapper it builds around it, how the swap installs it at
host +0xce0, and how the displaced wrapper is destroyed, including
the +0xb8-gated teardown that runs only for some old wrappers?

- Component: node #94 global member replace. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5169da0..0x516a2d9` (1337 bytes, FDE
  0x1317004, LSDA 0xbd8b59). The window takes one argument, the host
  in rdi, and returns void. Its landing-pad cleanup lives in the
  region immediately before it, `0x5169cea..0x5169d9b` (177 bytes,
  FDE 0x1317058, LSDA 0xbd8b7d), excerpted whole as cleanup.txt; the
  window's landing-pad stubs jump into that region's staged entries.
- The guard. If the host +0xa60 byte is nonzero, the function
  returns at once: nothing is built, nothing is swapped. This is the
  same guard the #2003 thunk reuses (it forwards only when the
  options +0x35 byte and host +0xa60 are both zero): a set +0xa60
  means the global member is not to be touched.
- The member build, end to end. A fresh 0x80 object is allocated
  (new), a hook object is constructed on the stack at rsp+0x30 by
  0x5311bc0 (by contract), and the member's +0x8/+0x20 pair is
  zeroed by 0x541ca90. The installs are: vtable address points
  0x575b230 at +0x00, 0x575b1f8 at +0x38, 0x5757be0 at +0x40;
  +0x30 = host +0xc58; +0x48 = host +0x10; +0x58 = 0; +0x5a = host
  +0x31 byte XOR 1; +0x60 = host +0x6c zero-extended; +0x68, +0x6c
  and +0x70 = 0; +0x78 = host +0x60; +0x28 = 0. Then +0x50 is filled
  from the host +0xa58 object's +0x90 virtual, called directly.
  Three differences from the #2011 construction are pinned: +0x58 is
  0 here where #2011 seeds 0x100; +0x50 comes from host +0xa58 with
  a plain +0x90 call where #2011 dispatches host +0xa50 through
  +0x90/+0x98; and there is no probe gate, so +0x28 stays 0 where
  #2011 installs host +0xc60 under its gate.
- The hook call. After the member is built, the hook object's +0x48
  field is read; when it is non-null it is called with (hook +0x38,
  hook +0x38, 3) — the same call the cleanup region repeats. A null
  hook is skipped. The code 3 is recorded literally; its meaning is
  unresolved.
- The wrapper build and swap. A 0xe8 object is allocated and filled
  by 0x5196de0 (by contract) with (the new buffer, the address of
  the new-member slot, host +0x08, 0, a zeroed 16-byte stack slot,
  stack 0); r9 is not written in this window. The new member's
  construction reference is then released through its +0x8 virtual,
  and the stack string handed to the builder is freed with sized
  delete[] when it is a heap string. The swap is: old = host +0xce0;
  host +0xce0 = the new wrapper. A null old wrapper returns at once.
- The old-wrapper destruction, end to end. When the old wrapper's
  +0xb8 byte is nonzero, its +0xb8 is cleared, its +0xc0 array of
  16-byte elements is reordered by 0x5164da0/0x5164af0 and the
  insertion/search/shift loops (by contract), each remaining element
  is released through its +0x8 field, the +0xc8 end is rewritten,
  the +0x98 callback is invoked with (old +0xa0, old +0xa8) when
  non-null, each +0xb0 list node (0x20 bytes) is serviced by
  calling its +0x00 field with (node +0x8, node +0x10) and freeing
  it, and +0x98/+0xb0 are zeroed. When +0xb8 is zero this whole arm
  is skipped. The common tail then runs in both cases: the +0xc0
  array buffer is freed with sized delete[] (size old +0xd0 minus
  old +0xc0) when non-null; old +0x98 is drained via 0x541cab0;
  the +0x80 intrusive list is walked (sentinel &old+0x80, next at
  node +0x00) freeing each node's +0x10/+0x20 string with sized
  delete[] (size +0x20 value + 1) unless +0x10 equals the node's
  +0x20 address (the inline case, skipped) and then the 0x30-byte
  node; the +0x60 list is walked (next at node +0x10) calling
  0x5165380 on each node's +0x18 field (by contract) and freeing
  the 0x28-byte node; the three (pointer, end) strings at +0x30,
  +0x18 and +0x00 are freed with sized delete[] (size end minus
  pointer) when non-null, in that order; finally the 0xe8 wrapper
  itself is freed by a tail jump to delete[].
- The cleanup region, staged. The window's landing-pad stubs jump
  into cleanup.txt at the stage matching how far construction got:
  free the member +0x70 detail when non-null, reset the member
  vtable to 0x57593f8, drain member +0x8 via 0x541cab0, call the
  hook when set, delete the 0x80 member — or, for the later stages,
  release via the member +0x8 virtual, call 0x4f95ab0 on the member
  (by contract) and delete the 0xe8 wrapper — each path ending in
  a canary check and _Unwind_Resume. This mirrors the #2011
  cleanup shape (same +0x70 free, same vtable reset, same drain).
- Claim status: observation for the window bounds, the guard rule,
  the member field installs, the hook call rule, the wrapper-build
  call order, the swap, the old-destruction order and both +0xb8
  arms, and the census; inference for the names "host", "member",
  "wrapper" and "hook" (roles, not class names); by contract for
  the wrapper builder, the hook constructor, the reorder helpers
  and loops, the +0x60-list helper, the member virtuals and the
  cleanup helper; unresolved for the items listed in records.json.
- Not a duplicate: #2003 reads the member lazily from shards and
  returns a 0xc8 wrapper — it does not replace host +0xce0, and it
  explicitly leaves this replace function unsubmitted while noting
  the shared prologue and guard. #2011 builds the same-shaped
  member but never wraps, swaps or destroys anything, and differs
  on +0x58, the +0x50 source and the probe gate as pinned above.
  The #1982 callback-flush teardown family is not re-claimed here.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them
  (including `endbr64` at each window entry) are genuine
  instructions present in the target binary, not placeholders;
  the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
  The packet JSON holds semantic records only — no
  per-instruction mnemonic list — and the packet carries its own
  runnable verify script plus the excerpt generator and census
  script, so the checker behind "ALL CHECKS PASSED" is visible
  in the diff.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: upstream open list, no 0x5169da0 or
  global-member-replace title; the window's 3 direct call sites
  are 0x50e33db, 0x50ea47b and 0x513159d, each confirmed as a real
  call instruction in objdump output). The 0x516d110 lookup
  variant and the 0x516b130 Seek remain unmapped and are not
  claimed here.
- Reproduction: objdump command recorded in export_excerpts.py;
  run it from the repository root to regenerate every excerpt.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: this VM has no cargo/rustc,
  no git-lfs and no Ghidra/Java, so no Rust reconstruction or
  binary execution is claimed; pytest is not installed, so the
  pytest-style test file runs under plain python3 via its
  `__main__` runner. The model is pure Python over the pinned
  field rules, not a run of the target binary.
