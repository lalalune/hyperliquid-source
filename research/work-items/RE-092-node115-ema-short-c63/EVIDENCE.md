# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3ee20–0x4d3ef2d` (269 bytes), `.eh_frame` offset `0xf17b44`
- Witnesses: tag-5 gate at `0x4d3ee33`, sentinel check at `0x4d3ee5c`, helper calls at `0x4d3ee6e` and `0x4d3eec0`, payload writes at `0x4d3ee82` and `0x4d3eed7`, and second-slot check at `0x4d3eee7`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
