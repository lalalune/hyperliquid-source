# RE-001: map node #115 sentinel chain dispatch 0x5d2efc0 / 0x5d2ef10 / 0x5d2f070

## Task

RE-001. Bounded question: what do the three sentinel functions at
0x5d2efc0, 0x5d2ef10, and 0x5d2f070 compute — the default implementations
of vtable slots 0x70, 0x78, and 0x98 that the chain-walk getters of the
previous work item compare against — and how does their dispatch rule
complete the getters' walk?

## Evidence

- Artifact: work/hl-node-115.bin, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Packet: research/work-items/RE-001-sentinel-chain-dispatch-115/ — semantic
  records.json only (no per-instruction mnemonic list); whole-function
  verbatim excerpts for all three windows; frames.txt; relocations.txt;
  verify.py, export_excerpts.py and census.py committed in the packet;
  MANIFEST.sha256. Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders. The
  objdump command for each excerpt is recorded in export_excerpts.py.
- Windows: sentinel slot 0x70 0x5d2efc0..0x5d2f06a (170 bytes);
  sentinel slot 0x78 0x5d2ef10..0x5d2efba (170 bytes);
  sentinel slot 0x98 0x5d2f070..0x5d2f132 (194 bytes).
- Semantics, stated literally: each sentinel takes a chain node in rdi
  and walks the chain linked through each node's +0x38 field. With
  prev starting at the sentinel's own address (its global holds that
  address at runtime via an R_X86_64_RELATIVE relocation), it steps to
  the next node, reads that node's vtable slot, and tail-jumps to the
  slot when it differs from prev; otherwise it steps on with prev
  updated to that slot. After eight matching nodes it takes the ninth
  node's slot unconditionally. The receiver's own slot is never read,
  and the differing slot receives every original argument unchanged
  except rdi, which is replaced by the differing node.
- Census (whole-file scan, reproduced by the packet's census.py): each
  sentinel has 0 direct calls and 0 tail jumps in .text, and appears
  as the addend of four R_X86_64_RELATIVE relocations — three
  .data.rel.ro slots plus the chain-walk getter's .got global
  (0x64ecde0, 0x64ece30, 0x64ecdf0 respectively) — so the sentinels are
  reached only through vtable slots and those globals, never by a
  direct call in this binary.
- Unknowns (kept separate): the domain meaning of the chain and the
  slots is not claimed; the dispatched slots are class-dependent
  virtual functions left by contract; which classes' vtables the three
  non-global RELATIVE slots belong to is not claimed; a chain that ends
  before the dispatch resolves is refused by the model rather than
  given an invented result.

## Verification

- Packet checker ALL CHECKS PASSED: digest, provenance, manifest,
  excerpt regeneration byte-for-byte from a fresh objdump run, sampled
  + 3 gate instructions byte-for-byte vs fresh objdump and raw binary,
  frames, census, model tests.
- 8 model tests pass (tools/sentinel_chain_dispatch_115.py,
  tests/test_sentinel_chain_dispatch_115.py): first-node differ,
  differ at each level 2–8, ninth-node fall-through (matching and
  differing), receiver slot never read, all three slots, chain
  exhaustion, missing-field guards, packet checks.
- Environment limits, stated honestly: this VM has no cargo/rustc, no
  git-lfs, and no Ghidra/Java, so no Rust reconstruction is claimed.
  `make doctor` reports analysis_ready false on missing providers
  (pre-existing); `make verify` / `make catalogue-check` fail on the
  LFS-pointer artifact here (pre-existing — this packet binds to the
  materialized work/hl-node-115.bin instead); pytest is not installed,
  so the pytest-style file ran under plain python3 via its `__main__`
  runner.
