# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3cb30, 0x4d3ccad)`, 381 bytes
- `.eh_frame` offset: `0xf174f8`
- Witnesses cover the `+0x90` scalar gate, repeated subtract/cmov/call groups, and the final `+0x68` group entry.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3cb30` include `0x51d1cc1` (`0x51d1c60` FDE, call), `0x4d3d12b` (`0x4d3cf40` FDE, jmp).
