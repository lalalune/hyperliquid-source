# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e0c0–0x4d3e194` (212 bytes), FDE VA `0xf17824`
- Witnesses: initial tag comparison at `0x4d3e0c8`, length comparison at `0x4d3e0f2`, payload helper call at `0x4d3e15a`, and trailing tag checks at `0x4d3e120`/`0x4d3e178`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3e0c0` include `0x4e0955c` (`0x4e08ed0` FDE, call).
