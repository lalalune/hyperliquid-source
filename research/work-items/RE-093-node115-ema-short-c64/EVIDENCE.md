# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3ef30–0x4d3f041` (273 bytes), `.eh_frame` offset `0xf17b74`
- Witnesses: tag gate at `0x4d3ef43`, input increment at `0x4d3ef68`, sentinel check at `0x4d3ef6f`, helper calls at `0x4d3ef82` and `0x4d3efc2`, payload writes at `0x4d3ef99` and `0x4d3efd6`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
