# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e4f0–0x4d3e53d` (77 bytes), `.eh_frame` offset `0xf17930`
- Witnesses: primary allocator call at `0x4d3e4f9`, sentinel stores at `0x4d3e50e`/`0x4d3e511`, record stores at `0x4d3e515`/`0x4d3e520`, and fallback allocator call at `0x4d3e537`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
