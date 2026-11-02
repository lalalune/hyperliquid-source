# RE-001: map node #94 probe-gated lookup (0x516ca20)

Task: RE-001 (#94 function map). Bounded question: how does node #94
turn a key range into a driver call — what gate, what member
resolution, what probe filter, and what the driver returns?

- Component: node #94 probe-gated lookup. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x516ca20..0x516d0d4` (1716 bytes, FDE
  0x1317208, LSDA 0xbd8ca9). The window's 9 direct callers are
  listed in records.json; each was confirmed as a real call
  instruction in objdump output.
- The flow, end to end. (1) Gate: host +0xc18 null returns 0 at
  once, with nothing else done. (2) Member resolution: the
  0x516aa20 thunk built in #2003 (null unless the options argument
  +0x35 and host +0xa60 are both zero, else a tail jump into the
  #2003 sharded access 0x516a390) yields a member or null. A
  non-null member feeds the key slice (range start..end-8, the
  8-byte trailer stripped as in the #1985 entry check) to the
  0x51922d0 transform; its result max-updates the stack-arg-0x18
  output (updated only when larger) and, when the r8 string
  argument is non-null, replaces that string wholesale with the
  pair looked up from the member +0x68 table via the member +0x90
  pointer. (3) Probe filter: host +0xc60 null skips the probe;
  otherwise the probe slice is range start with length
  (range end - range start - 8) - (host +0x10 object) +0x28, the
  same form as the #1994 seek gate. Host +0x30 byte zero takes
  the virtual variant (the host +0xc58 object +0xa0 predicate
  virtual, then its +0x98 transform virtual whose result is
  hashed); nonzero takes the direct-hash variant. The loop is
  the #1994 probe exactly: base = (count * hash32) >> 32, the
  two-bit mask of hash32 * 0x9e3779b97f4a7c13 rotated right 12
  per round, round 0 always tested. A hit calls the driver; a
  miss writes -1 to the stack-arg-0x20 output and, when the
  r9-object flag byte says so, installs the {6, 0, null} record
  into the r9 object (skipped when its first byte is already 2;
  the caller's post-move free of the temporary is dead because
  the move zeroes it). (4) Driver: 0x516c7e0 (503 bytes,
  excerpted whole) receives 14 arguments including pointers to
  the two out bytes; after it returns, the -0x82 byte is the
  function's return value and the -0x81 byte gates the same
  status-6 install. The driver itself calls the 0x516b130 Seek
  implementation, which is the suggested next phased item, not
  claimed here. (5) Epilogue: perf +0x120 counter, member
  release through its +0x8 virtual when non-null, timer
  destruction when the start value is nonzero (the #1994
  destructor 0x5165320, excerpted whole), then return.
- Claim status: observation for the window bounds, the gate, the
  thunk and transform call sites, the max-update and pair
  lookup arithmetic, the probe loop math, the driver call
  arguments and out-flag protocol, the miss sentinel and
  status install, the epilogue order, the perf counters and
  the census; inference for the names "host", "member",
  "probe table" and "driver" (roles, not class names);
  unresolved for the items listed in records.json, including
  the transform's first call 0x51910a0, the hash helper
  internals, and the driver's own semantics.
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
  (checked this cycle: upstream open list has 3 entries, none
  for 0x516ca20). The thunk is #2003's, the probe and timer are
  the #1994 forms, the trailer strip is #1985's, the move
  helper is read here from its own disassembly; none of those
  items is re-claimed. The driver 0x516c7e0 and the Seek
  0x516b130 are cited only as the consumer chain, not mapped.
- Reproduction: objdump command recorded in export_excerpts.py;
  run it from the repository root to regenerate every excerpt.
