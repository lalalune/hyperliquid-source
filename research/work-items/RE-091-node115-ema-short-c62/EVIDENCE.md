# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3ed00–0x4d3ee12` (274 bytes), FDE VA `0xf17b10`
- Witnesses: tag gate at `0x4d3ed13`, input increment at `0x4d3ed38`, sentinel check at `0x4d3ed40`, helper calls at `0x4d3ed53` and `0x4d3ed93`, payload writes at `0x4d3ed6a` and `0x4d3edf5`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open.
