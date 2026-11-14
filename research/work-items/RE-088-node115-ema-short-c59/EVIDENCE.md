# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e890–0x4d3e9a2` (274 bytes), FDE VA `0xf17a44`
- Witnesses: tag gate at `0x4d3e8a3`, offset adjustment at `0x4d3e8c8`, helper calls at `0x4d3e8e3` and `0x4d3e923`, payload writes at `0x4d3e8fa` and `0x4d3e937`, and alternate sentinel check at `0x4d3e95f`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3e890` include `0x5209206` (`0x5209100` FDE, call).
