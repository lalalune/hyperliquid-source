# RE-001: map node #94 batch lookup (0x516d110)

Task: RE-001 (#94 function map). Bounded question: how does node #94
look up a whole range-set at once — what gate, what collection,
what probe filter, and what one driver call per passing entry does?

- Component: node #94 batch lookup. One window, extracted from the
  digest-verified work binary (SHA-256 `3b7179cd…c0459f`):
  `0x516d110..0x516dc97` (2951 bytes, FDE 0x1317268, LSDA
  0xbd8cdf). Its 2 direct callers are listed in records.json;
  each was confirmed as a real call instruction in objdump output.
- Relation to #2009: this is the batch sibling of the
  probe-gated lookup 0x516ca20, which sits immediately before it
  in the binary (its window ends at 0x516d0d4, where this
  function's landing-pad stub lives). Same host gate (+0xc18),
  same perf/timer prologue and epilogue, same driver 0x516c7e0,
  same transform 0x51922d0, same hash 0x5422e70, same probe
  math as #1994 — but over a range-set object instead of one
  key range, with one driver call per passing entry instead of
  one driver call total.
- The flow, end to end. (1) Gate: host +0xc18 null returns 0 at
  once, nothing else done. Perf prologue and timer record are
  the #2009 forms (perf-level slot 0x5777ef8, TLS byte
  fs:0-0x10a8, timer object 0x5242050, destructor 0x5165320).
  (2) Flag: -0x561 = options +0x35 when nonzero, else whether
  host +0xa60 is nonzero — nonzero exactly when the #2003
  thunk would return null. (3) Range scan and collection: the
  range-set (rdx) carries a base object (+0xe00 entry-pointer
  table, +0xf08 skip bitset, +0xf10 counter), start (+0x08),
  end (+0x10) and two mask words (+0x18, +0x20); the skip word
  for an index is their OR. Set-bit indices are skipped.
  Each clear-bit entry contributes its 16-byte view from
  entry +0x20 to the stack arrays (views at -0x240, indices
  at -0x440, count at -0x570, pre-initialised with 32 empty
  views whose pointer is 0x1e629b, the NUL byte ending a
  .rodata path string, i.e. an empty view): when the flag is
  nonzero the view is copied directly; when the flag is zero
  the entry's view must pass the host +0xc58 object's +0xa0
  predicate and is then replaced by that object's +0x98
  transform result view (a (ptr, length) pair returned in
  rax:rdx). (4) Probe filter: each collected view is hashed
  by 0x5422e70 with seed 0xbc9f1d34 against the host +0xc60
  table (count at +0x00, words at +0x08, rounds at +0x04):
  base = (count * hash32) >> 32, words[base] prefetched, and
  round k tests words[base XOR k] against the two-bit mask of
  hash32 * 0x9e3779b97f4a7c13 rotated right 12 per round;
  every tested round must contain both mask bits, and round 0
  is always tested even when rounds is 0. A failing view
  only marks its index bit done. A passing view increments
  the +0x200 perf counter when the TLS perf byte exceeds 1.
  (5) Driver loop: for each passing entry, when the flag is
  zero the member-feed runs first — sharded access 0x516a390
  called directly (host, options, (entry +0x08 object +0x10
  field's -8 qword) >> 8, r8b flag byte), transform 0x51922d0
  on the slice (entry +0x08 object's +0x08 pointer, length
  (+0x10) - (+0x08) - 8, the #1985 trailer strip), the result
  max-updates entry +0x68, and when the member +0x90 pointer
  is non-null the whole string at entry +0x90 is replaced
  via basic_string::_M_replace with the pair at member +0x68
  table +0x30 + ((member +0x90 - table +0x18) / 8) * 16, the
  #2009 pair rule; the member is then released through its
  +0x8 virtual. Then the driver 0x516c7e0 is called with 14
  arguments (host, entry +0x08, entry +0x68, 1, rcx argument,
  entry +0x71, entry +0x80 slot's +0x50 target, entry +0x88,
  entry +0x90, entry +0x48 object, entry +0x50, the -0x520
  context, the -0x522 result byte pointer, the -0x521 flag
  byte pointer; -0x521 was preset to (entry +0x48 object's
  first byte == 6)). (6) Driver outcomes: a nonzero result
  byte takes the sweep path — the entry +0x80 pair is moved
  into its slot and its second word added to base +0xf10,
  the current index bit is set in base +0xf08, the host
  +0x50 object's +0xb0 virtual is called with (object,
  0x19, 1) when host +0x50 is non-null, and, unless base
  +0xf10 has reached options +0x78, every later clear-bit
  entry in the range gets its +0x48 record set to {10, 0,
  null} (old +0x8 pointer freed with operator delete[]) and
  its bit set; a zero result byte with a nonzero flag byte
  installs {6, 0, null} into the current entry's +0x48
  record the same way; both zero moves to the next item.
  (7) Epilogue: perf +0x120 counter when the TLS byte
  exceeds 1, timer destruction when its start value is
  nonzero, then return. The two landing pads (0x516dc86,
  0x516dc92) tail-jump into the shared stub 0x516d0d4,
  excerpted whole: it releases the member through its +0x8
  virtual (first pad only), destroys the timer when started,
  checks the stack canary and resumes unwinding.
- Claim status: observation for the window bounds, the gate,
  the range-set layout, the skip-word OR, the flag rule, both
  collection forms, the probe math, the driver argument list
  and out-byte protocol, the member-feed call sequence and
  pair rule, both status installs, the sweep's counter and
  bitset updates and the +0xb0 callback, the perf counters
  and the census; inference for the names "host", "member",
  "range-set", "probe table" and "driver" (roles, not class
  names); unresolved for the items listed in records.json,
  including the driver's own semantics (by contract, as in
  #2017), the transform's internals, the exact phase order
  between the first range scan and the collection pass (the
  control flow reuses one cursor slot across phases; the
  phases above are the observable sequence, not a claim
  about that slot's value at each jump), and the return
  value on the non-gate paths (only the gate's 0 is pinned).
- Note on evidence text: the raw disassembly excerpts are
  verbatim objdump output. Instruction mnemonics appearing
  in them (including `endbr64` at each window entry) are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled
  instructions byte-for-byte against a fresh objdump run
  and the raw binary. The packet JSON holds semantic
  records only — no per-instruction mnemonic list — and the
  packet carries its own runnable verify script plus the
  excerpt generator and census script, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: the upstream open list has no
  0x516d110/batch entry). The driver is #2017's, the
  transform and pair rule are #2009's, the probe math is
  #1994's, the access is #2003's, the timer destructor is
  #1994's — none of those items is re-claimed. The Seek
  0x516b130 remains the suggested larger phased item.
- Reproduction: objdump command recorded in
  export_excerpts.py; run it from the repository root to
  regenerate every excerpt.
