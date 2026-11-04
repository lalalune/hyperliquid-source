# RE-001: map node #115 hash-table find-or-insert (0x5f0e660)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f0e660 do end to end — how does it find a key in a
bucket's run, and when it misses, how does it allocate, optionally
rehash, and splice a new node in?

- Component: node #115 hash-table find-or-insert. One window,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f0e660..0x5f0e85f` (511 bytes; FDE .eh_frame offset 0x745a04,
  length 0x4c, CIE 0x730230; LSDA 0x414ab0 decoded in records.json).
  The window immediately follows the RE-001 hash-table rehash
  window (0x5f0e520..0x5f0e65d) after int3 padding, and it is the
  rehash's first caller: its rehash call site is 0x5f0e7e0.
- Claim status: observation for the window bounds, the hash call
  and seed, the bucket computation, the full walk (hash, length,
  memcmp, run-end rule), both splice arms, the _M_need_rehash call
  and its arguments, the rehash call and its arguments (including
  the saved this+0x28 restore pointer, which resolves the rehash
  packet's open unknown about the callee's third argument: this
  caller passes the address of a stack copy of this+0x28, and the
  callee's landing pad writes the saved value back), the element
  count rule, the LSDA call sites, the landing pad and the caller
  census; inference for the names "hash-table find-or-insert",
  "before-node" and "head field" (they describe the observed
  roles) and for the operator[] reading of the return; unresolved
  for the items listed in records.json (hash body, caller identity,
  exact C++ spelling, zero-count reachability).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry and at the landing pad) are genuine
  instructions present in the target binary, not placeholders; the
  packet checker re-verifies sampled instructions byte-for-byte
  against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot, no 0x5f0e660 title). It is
  not a duplicate of the neighbouring rehash packet: that packet
  rebuilds the whole table, while this window is the lookup-plus-
  insert entry point that calls it. The rehash body is cited from
  that packet, not re-claimed here; the single direct caller at
  0x5f0f052 is a call site only, not mapped here.
- Evidence format: the packet JSON holds semantic records only —
  branch sites, guards, insertion rules, LSDA call sites and the
  census. Instruction-level detail lives only in the verbatim
  whole-function excerpt. The verify script and the excerpt
  generator are committed in the packet, so the checker behind
  "ALL CHECKS PASSED" is visible in the diff.
- Environment limits (stated honestly): no cargo/rustc, no
  git-lfs, no Ghidra/Java on this VM, so no Rust reconstruction
  and no binary execution; `make doctor` fails on the missing
  rust/Ghidra providers (pre-existing). The model and its tests
  are Python only and were run under plain python3 (pytest is not
  installed on this VM).
