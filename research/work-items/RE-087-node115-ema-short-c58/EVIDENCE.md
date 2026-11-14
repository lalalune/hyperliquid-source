# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e770–0x4d3e881` (273 bytes), FDE VA `0xf17a10`
- Witnesses: tag gate at `0x4d3e783`, sentinel check at `0x4d3e7af`, first helper call at `0x4d3e7c2`, payload write at `0x4d3e7d9`, second-slot check at `0x4d3e7f1`, and alternate helper call at `0x4d3e850`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3e770` include `0x5ad0a84` (`0x5ad09f0` FDE, call).
