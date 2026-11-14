# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e9b0–0x4d3eabd` (269 bytes), `.eh_frame` offset `0xf17a78`
- Witnesses: tag gate at `0x4d3e9c3`, sentinel check at `0x4d3e9ec`, helper calls at `0x4d3e9fe` and `0x4d3ea50`, payload writes at `0x4d3ea12` and `0x4d3ea67`, and second-slot check at `0x4d3ea7b`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
