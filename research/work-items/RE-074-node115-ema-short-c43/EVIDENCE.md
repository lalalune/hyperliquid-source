# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3ccb0, 0x4d3cd63)`, 179 bytes
- `.eh_frame` offset: `0xf1753c`
- Witnesses cover the shared comparator call, `+0x35` byte comparison, `+0x30` integer comparison, and terminal `+0x34` field.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3ccb0` include `0x4d3c179` (`0x4d3bbe0` FDE, jmp).
