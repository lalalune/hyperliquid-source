# RE-001: map node #115 hash-table rehash (0x5f0e520)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f0e520 do end to end — how does it size and allocate
the new bucket array, how does it reinsert every node, and how does
it release the old array?

- Component: node #115 hash-table rehash. One window, extracted from
  the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f0e520..0x5f0e65d` (317 bytes; FDE .eh_frame offset 0x7459c4,
  length 0x3c, CIE 0x730230; LSDA 0x414a94 decoded in records.json).
  The window immediately follows the RE-001 spinlock-aggregate
  window (0x5f0e2d0..0x5f0e51b) after int3 padding.
- Claim status: observation for the window bounds, the count guards,
  the single-bucket path, the allocation, the detach, the bucket
  computation, both insertion arms, the most-recently-started slot
  rewrite, the old-array release rule, the install, the LSDA call
  sites, both landing pads and the caller census; inference for the
  names "hash-table rehash", "before-node" and "head field" (they
  describe the observed roles: slots holding the node preceding a
  bucket's first node, and the +0x10 field holding the list head);
  unresolved for the items listed in records.json (third argument,
  caller identity, +0x28 role, +0x18/element-count maintenance).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot, no 0x5f0e520 title). It is
  not a duplicate of the neighbouring packets: the spinlock window
  reads a table and returns a total, while this window rewrites the
  table itself (new array, reinserted nodes, released old array).
  The single direct caller at 0x5f0e7e0 is a call site only; the
  caller function was not mapped and is not claimed here.
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
