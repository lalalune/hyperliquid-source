# RE-001: map node #94 seek driver with its context build, +0x60 dispatch and inline loop (0x516c7e0)

Task: RE-001 (#94 function map). Bounded question: how does node #94
drive a seek over an iterator — what context it builds from the host
and its arguments, when it delegates to the host object's +0x60
implementation, and when it instead runs the loop itself with the
0x516b130 Seek fixed as the callback?

- Component: node #94 seek driver. Two windows, extracted from the
  digest-verified work binary (SHA-256 `3b7179cd…c0459f`):
  the driver `0x516c7e0..0x516c9d7` (503 bytes, FDE 0xf7d43c,
  no LSDA) and the generic loop `0x51651e0..0x51652ac` (204 bytes,
  FDE 0xf7cd3c, no LSDA) that the driver compares its +0x60 slot
  against. The driver is the consumer the #2009 probe-gated lookup
  calls on a probe hit, and it is also called from the 0x516d110
  lookup variant; both call sites are listed in records.json and
  were confirmed as real call instructions in objdump output.
- The context build, end to end. The driver takes six register
  arguments (host in rdi, a slice struct pointer in rsi, a qword in
  rdx, a byte in cl, a qword in r8, a qword in r9) and eight stack
  arguments (stack0..stack7, at the caller's stack slots the prologue
  reads). It copies them into a context struct at rsp+0x10, in this
  exact layout: +0x00 = stack3; +0x08 = the slice struct pointer;
  +0x10 = stack6; +0x18 = stack7; +0x20 = stack0; +0x28 = stack1;
  +0x30 = 0xffffffffffffff (the 56-bit all-ones sentinel, the result
  slot the Seek callback may overwrite by contract); +0x38 = the
  pair (stack2, host +0x58); +0x48 = stack4; +0x50 = rdx; +0x58 =
  the pair (host, host +0x60); +0x68 = host +0x50; +0x70 = the word
  whose low byte is host +0x31 and whose high byte is cl; +0x78 =
  the pair (host +0xc70, r8); +0x88 = r9; +0x90 = the host +0x68
  byte; +0x98 = host +0x6c as a zero-extended qword. A stack canary
  (fs:0x28) is saved at rsp+0xb8 and checked on exit; a mismatch
  tail-calls __stack_chk_fail.
- The +0x60 dispatch. The driver loads the host +0xa50 object's
  vtable +0x60 slot and compares it with the known generic loop
  0x51651e0. If it differs, the driver delegates: it calls that
  slot with (the +0xa50 object, the slice struct, the context, the
  0x516b130 Seek as callback) and then falls through to the exit
  below — the delegation itself never writes the result; the exit
  does. If it equals 0x51651e0, the driver does NOT call it; it
  runs the loop inline, with Seek fixed as the callback and the
  built context as the callback context.
- Iterator acquisition, shared by the driver and the generic loop.
  The +0x98 field of the +0xa50 object's vtable is compared against
  GOT slot 0x57783c0 (R_X86_64_RELATIVE addend 0x5164750, the same
  slot the #2009 driver check and the #2011 member construction
  check). Equal takes the +0x90 virtual with (the +0xa50 object);
  unequal calls the +0x98 field value directly with the same
  argument. The result is the iterator.
- The loop, identical in the driver and the generic loop. The
  target slice is (slice struct +0x08, length slice struct +0x10
  minus slice struct +0x08); the iterator's +0x30 virtual is called
  with (iterator, a stack slice of that pointer/length, slice
  struct +0x00). Then, while the iterator's +0x10 virtual reports
  valid: the callback is called with (context, the iterator's
  +0x18 virtual result); a false callback result ends the loop;
  a true result calls the iterator's +0x20 virtual (advance) and
  re-checks validity. The generic loop takes its callback and its
  callback context as arguments (rdx = context, rcx = callback)
  and returns void; the driver fixes both (context = the built
  struct, callback = Seek 0x516b130) and, on every exit path, writes
  context +0x30 to the stack5 out pointer (the r12 pointer). If
  Seek never overwrites +0x30, the out value is the sentinel.
- The Seek itself (0x516b130, 5793 bytes) is by contract only in
  this item: its internals are a separate, larger item, and no
  claim about what it reads or writes beyond the +0x30 result slot
  contract above is made here. The iterator virtuals (+0x10, +0x18,
  +0x20, +0x30, +0x90, +0x98) are likewise by contract; their call
  order, arguments and branching are observation.
- Claim status: observation for both window bounds, the context
  layout, both dispatch rules, the loop order and the census;
  inference for the names "host", "slice struct", "context" and
  "iterator" (roles, not class names); by contract for Seek, the
  iterator virtuals and the +0x60 delegate internals; unresolved
  for the items listed in records.json — notably, no RELATIVE
  slot, qword reference or direct call for 0x51651e0 was found in
  this binary, so the known +0x60 implementation is pinned only by
  the driver's identity comparison, and which vtables would carry
  it at +0x60 in a fuller build is not established here.
- Not a duplicate of #2009: #2009 cites this driver only as the
  callee its lookup calls on a probe hit, with the driver loop
  explicitly not claimed; this item maps the driver itself. The
  #2011 construction's +0x90/+0x98 dispatch is the same pattern on
  the same object family, but on a different function.
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
  (checked this cycle: upstream open list has 4 entries, none for
  0x516c7e0 or the seek driver). The 0x516b130 Seek, the 0x516d110
  caller and the +0x60 delegate internals are not claimed here.
- Reproduction: objdump command recorded in export_excerpts.py;
  run it from the repository root to regenerate every excerpt.
