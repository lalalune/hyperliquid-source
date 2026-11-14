# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3ccb0, 0x4d3cd63)`, 179 bytes
- `.eh_frame` offset: `0xf1753c`
- Witnesses cover the shared comparator call, `+0x35` byte comparison, `+0x30` integer comparison, and terminal `+0x34` field.
- Identity controls reject truncated and first-byte-mutated captures.
