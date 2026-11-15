# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3cd70, 0x4d3cf3a)`, 458 bytes
- `.eh_frame` offset: `0xf17568`
- Witnesses cover the initial shared comparator, signed `+0x68` normalization, and later `+0x70/+0x88` groups.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3cd70` include `0x4d3d3f8` (`0x4d3cf40` FDE, call), `0x4d3d447` (`0x4d3cf40` FDE, call), `0x4d3d149` (`0x4d3cf40` FDE, jmp).
