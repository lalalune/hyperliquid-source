# RE-001: map node #94 member construction with probe install (0x5169250)

Task: RE-001 (#94 function map). Bounded question: how does node #94
build a member object from a host and an inner object — what fields
it installs, when it installs the probe table, and how it obtains
the member's +0x50 field?

- Component: node #94 member construction. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5169250..0x5169377` (295 bytes, FDE
  0x1316f24, LSDA 0xbd8b27). The window's 10 direct callers are
  listed in records.json; each was confirmed as a real call
  instruction in objdump output.
- The flow, end to end. (1) Factory: the inner object's +0x18
  virtual is called with (inner, 0x80, 0) and its result is the
  member; the member +0x8 subobject is zeroed by 0x541ca90
  (excerpted whole: it zeroes the qword at its argument and the
  qword 0x18 past it, i.e. member +0x8 and member +0x20). The
  factory's internals are by contract only; the 0x80 size matches
  the object the #2003 lazy build allocates with operator new.
  (2) Field installs, all by plain stores: vtable address points
  0x575b230 at +0x0, 0x575b1f8 at +0x38, 0x5757be0 at +0x40;
  +0x30 = host +0xc58; +0x48 = host +0x10; +0x58 (u16) = 0x100;
  +0x5a (u8) = host +0x31 byte XOR 1; +0x60 = host +0x6c u32
  zero-extended; +0x68 (u32) = 0; +0x6c (u16) = 0; +0x70 = 0;
  +0x78 = host +0x60; +0x28 = 0 unless the probe gate fires.
  (3) Probe gate: the probe path runs only when host +0xc58 is
  non-null AND the options +0x30 byte is 0 AND the options +0x31
  byte is 0. Any other combination takes the default path. On the
  probe path, member +0x28 = host +0xc60. (4) +0x50 dispatch: the
  default path calls the host +0xa50 object's +0x90 virtual with
  (that object, inner) and stores the result to member +0x50. On
  the probe path, the +0x98 field of *(host +0xa50) is compared
  against GOT slot 0x57783c0 (R_X86_64_RELATIVE addend 0x5164750,
  the same slot the #2009 driver checks); equal takes the +0x90
  virtual arm, unequal calls the +0x98 field value directly with
  the same two arguments. The function returns the member pointer.
  (5) Exception cleanup: the landing pad 0x516936b jumps to
  0x5169220 (excerpted whole), which frees member +0x70 with
  operator delete[] when non-null, resets the member vtable
  pointer to 0x57593f8, drains the member +0x8 subobject through
  0x541cab0 (excerpted whole), then resumes unwinding.
- Claim status: observation for the window bounds, the factory call
  site and its arguments, every field install, the probe gate, the
  +0x50 dispatch rule, the cleanup steps and the census; inference
  for the names "host", "options", "inner" and "member" (roles, not
  class names); by contract for the factory virtual, the +0x90
  virtual, the +0x98 direct-call target and the 0x541cab0 drain
  internals; unresolved for the items listed in records.json.
- Not a duplicate of #2003: the #2003 shard-member-access lazy
  build fills an object of the same shape inline, but this window
  is a separate function with 10 direct callers, it seeds +0x58
  with 0x100 where the #2003 fill seeds 0, its +0x50 source is the
  host +0xa50 object called with the inner object (the #2003 fill
  uses host +0xa58 called with 0, 0), and it alone carries the
  probe gate (+0x28 install and the +0x98 dispatch). None of
  #2003's bucket, CPUID, RNG or wrapper claims is re-made here.
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
  (checked this cycle: upstream open list has 1 entry, unrelated).
  The 0x541ca90 zeroing and the three vtable address points are
  shared with #2003's fill, but the construction, the +0x58 seed,
  the +0x50 source and arguments, and the probe gate are this
  window's own. The #2009 driver checks the same GOT slot on the
  same object family; the driver's loop is not claimed here.
- Reproduction: objdump command recorded in export_excerpts.py;
  run it from the repository root to regenerate every excerpt.
