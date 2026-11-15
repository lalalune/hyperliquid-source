# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e4f0–0x4d3e53d` (77 bytes), FDE VA `0xf17930`
- Witnesses: primary allocator call at `0x4d3e4f9`, sentinel stores at `0x4d3e50e`/`0x4d3e511`, record stores at `0x4d3e515`/`0x4d3e520`, and fallback allocator call at `0x4d3e537`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3e4f0` include `0x5ad09b7` (`0x5ad0940` FDE, call), `0x5ad0a67` (`0x5ad09f0` FDE, call).
