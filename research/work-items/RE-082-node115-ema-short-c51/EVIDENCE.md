# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3dde0–0x4d3df07` (295 bytes), `.eh_frame` offset `0xf177c8`
- Witnesses: tag loads at `0x4d3dde0` and `0x4d3de0b`, length comparison at `0x4d3de21`, bounded helper call at `0x4d3de8b`, and later tag comparisons at `0x4d3deba` and `0x4d3dee1`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
