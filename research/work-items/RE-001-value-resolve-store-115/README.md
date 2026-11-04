# RE-001: map node #115 value resolve-and-store (0x5f09e90)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f09e90 do end to end — how does it resolve a value
(either a directly supplied qword, or a four-way xor-fold of hash
calls) and store it truncated by a host width field?

- Component: node #115 value resolve-and-store. One whole function,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f09e90..0x5f09faf` (351 bytes; FDE .eh_frame offset 0x358aec,
  length 0x38, CIE 0, no LSDA asserted).
- Claim status: observation for the window bounds, the width gate,
  the direct-load path, the four hash call sites with their seeds
  and inputs, the xor-fold order, the width-truncated store arms
  and the no-store arms, the caller census; inference for the
  names "value", "host" and "out slot" (they describe the observed
  roles); unresolved for the items listed in records.json (the
  hash callee 0x61c3530's body, the exact C++ spelling, the
  meaning of the two slices and of the byte/qword hash inputs).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot plus a repository search
  for 5f09e90, no hit). It is not a duplicate of the neighbouring
  hash-table packets: those map the table itself (rehash,
  find-or-insert), while this window is a value-resolution helper
  called from five sites, including the large insert function at
  0x5f0e890 (call site 0x5f0ea4f) and two sites in the 0x5f0f3d0
  function. The hash callee 0x61c3530 (0x61c3530..0x61c389d, 877
  bytes) is cited by contract only, not re-claimed here.
- Evidence format: the packet JSON holds semantic records only —
  the width gate, the hash-fold call sequence, the store arms and
  the census. Instruction-level detail lives only in the verbatim
  whole-function excerpt. The verify script and the excerpt
  generator are committed in the packet, so the checker behind
  "ALL CHECKS PASSED" is visible in the diff.
- Environment limits (stated honestly): no cargo/rustc, no
  git-lfs, no Ghidra/Java on this VM, so no Rust reconstruction
  and no binary execution; `make doctor` fails on the missing
  rust/Ghidra providers (pre-existing). The model and its tests
  are Python only and were run under plain python3 (pytest is not
  installed on this VM). The hash callee's body is not modelled:
  tests inject a stub hash, so they pin the fold structure, the
  call order and the truncation, not the hash itself.
