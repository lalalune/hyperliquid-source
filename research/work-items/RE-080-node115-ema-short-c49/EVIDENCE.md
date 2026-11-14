# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3dbc0, 0x4d3dcc9)`, 265 bytes
- `.eh_frame` offset: `0xf17750`
- Witnesses cover the `+0x60` scalar gate and three repeated comparator groups.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3dbc0` include `0x4d3d3a3` (`0x4d3cf40` FDE, jmp).
