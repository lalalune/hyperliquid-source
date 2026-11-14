# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3eac0–0x4d3ebd1` (273 bytes), `.eh_frame` offset `0xf17aa8`
- Witnesses: tag gate at `0x4d3ead3`, input increment at `0x4d3eaf8`, sentinel check at `0x4d3eaff`, helper calls at `0x4d3eb12` and `0x4d3eb52`, payload writes at `0x4d3eb29` and `0x4d3eb66`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
