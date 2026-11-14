# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3f170–0x4d3f282` (274 bytes), `.eh_frame` offset `0xf17bdc`
- Witnesses: tag gate at `0x4d3f183`, input adjustment at `0x4d3f1a8`, sentinel check at `0x4d3f1b0`, helper calls at `0x4d3f1c3` and `0x4d3f203`, payload writes at `0x4d3f1da` and `0x4d3f217`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
