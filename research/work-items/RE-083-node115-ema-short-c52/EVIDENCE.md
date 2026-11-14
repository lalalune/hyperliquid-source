# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3df10–0x4d3e0b5` (421 bytes), `.eh_frame` offset `0xf177f8`
- Witnesses: flag tests at `0x4d3df15` and `0x4d3df23`, bounded arithmetic loop at `0x4d3df60`, stack-buffer writes at `0x4d3df9c` and `0x4d3e04d`, and helper calls at `0x4d3e01d` and `0x4d3e0a9`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
