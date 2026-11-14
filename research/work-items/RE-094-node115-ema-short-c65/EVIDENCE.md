# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3f050–0x4d3f161` (273 bytes), `.eh_frame` offset `0xf17ba8`
- Witnesses: tag gate at `0x4d3f063`, input increment at `0x4d3f088`, sentinel check at `0x4d3f08f`, helper calls at `0x4d3f0a2` and `0x4d3f0e2`, payload writes at `0x4d3f0b9` and `0x4d3f0f6`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
