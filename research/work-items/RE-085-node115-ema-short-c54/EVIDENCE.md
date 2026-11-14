# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3e400–0x4d3e44a` (74 bytes), FDE VA `0xf178c4`
- Witnesses: length comparison at `0x4d3e408`, helper call at `0x4d3e41c`, `0x18` record advances at `0x4d3e430`/`0x4d3e434`, and tail jump at `0x4d3e445`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3e400` include `0x4e0a29d` (`0x4e0a200` FDE, jmp).
