# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3d990, 0x4d3dbbe)`, 558 bytes
- `.eh_frame` offset: `0xf176f0`
- Witnesses cover normalization, jump-table dispatch, the first comparator call, and terminal byte-field path.
- Identity controls reject truncated and first-byte-mutated captures.
