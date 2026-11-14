# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3c990, 0x4d3ca91)`, 257 bytes
- `.eh_frame` offset: `0xf174cc`
- Witnesses cover tag tests, optional `+0x10/+0x28` fields, null branches, and terminal `+0x20` scalar ordering.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3c990` include `0x4d3c409` (`0x4d3bbe0` FDE, jmp).
