# RE-001: map node #115 chain-walk getters 0x5eee5d0 / 0x5eee660 / 0x5eee6f0 with head helper 0x5eee5b0

## Task

RE-001. Bounded question: what do the three getter-shaped functions at
0x5eee5d0, 0x5eee660, and 0x5eee6f0 compute from their (outer, out)
arguments, and how do they share the head helper at 0x5eee5b0?

## Evidence

- Artifact: work/hl-node-115.bin, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Packet: research/work-items/RE-001-chain-walk-getters-115/ — semantic
  records.json only (no per-instruction mnemonic list); whole-function
  verbatim excerpts for all four windows; frames.txt; relocations.txt;
  verify.py, export_excerpts.py and census.py committed in the packet;
  MANIFEST.sha256. Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders. The
  objdump command for each excerpt is recorded in export_excerpts.py.
- Windows: head 0x5eee5b0..0x5eee5c3 (19 bytes); getter slot 0x70
  0x5eee5d0..0x5eee654 (132 bytes); getter slot 0x78 0x5eee660..0x5eee6e4
  (132 bytes); getter slot 0x98 0x5eee6f0..0x5eee784 (148 bytes).
- Semantics, stated literally: head returns [[outer + 0x788] + 0x6b0].
  Each getter walks the chain linked through each node's +0x38 field,
  comparing each node's vtable slot (0x70, 0x78, or 0x98) against the
  previous slot — the head node's slot against the getter's sentinel
  global — and invokes the first slot that differs, storing its result
  into *out and returning 1. If the first four slots all match their
  predecessor, the fifth node's slot is invoked unconditionally. A null
  head returns 0 with *out untouched. The sentinel globals resolve at
  runtime via R_X86_64_RELATIVE relocations to 0x5d2efc0 (slot 0x70),
  0x5d2ef10 (slot 0x78), and 0x5d2f070 (slot 0x98).
- Census (whole-file scan, reproduced by the packet's census.py): the
  head helper has exactly 3 direct calls (the three getters' sites
  0x5eee5d8, 0x5eee668, 0x5eee6f8) and no other references; each getter
  has 0 direct calls, 0 tail jumps, 0 qword hits, and 0 RELATIVE
  addends (virtual-getter shape).
- Unknowns (kept separate): the domain meaning of the chain, the head,
  and the slots is not claimed; the invoked slots are class-dependent
  virtual functions left by contract; indirect callers are not covered
  by the census; a chain that ends before the walk resolves is refused
  by the model rather than given an invented result.

## Verification

- Packet checker ALL CHECKS PASSED: digest, provenance, manifest,
  excerpt regeneration byte-for-byte from a fresh objdump run, sampled
  + 3 gate instructions byte-for-byte vs fresh objdump and raw binary,
  frames, census, model tests.
- 13 model tests pass (tools/chain_walk_getters_115.py,
  tests/test_chain_walk_getters_115.py): head projection, null head,
  differ-at-each-level (nodes 1-4), fifth-node fall-through (matching
  and differing), receiver identity, per-slot sentinels, chain
  exhaustion, missing-field guards, packet checks.
- Environment limits, stated honestly: this VM has no cargo/rustc, no
  git-lfs, and no Ghidra/Java, so no Rust reconstruction is claimed.
  `make doctor` reports analysis_ready false on missing providers
  (pre-existing); `make verify` / `make catalogue-check` fail on the
  LFS-pointer artifact here (pre-existing — this packet binds to the
  materialized work/hl-node-115.bin instead); pytest is not installed,
  so the pytest-style file ran under plain python3 via its `__main__`
  runner.
