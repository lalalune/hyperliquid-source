# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3d8e0, 0x4d3d987)`, 167 bytes
- `.eh_frame` offset: `0xf176b8`
- Witnesses cover the initial shared comparator, bounded loop setup, word/byte loop comparisons, and final length ordering.
- Identity controls reject truncated and first-byte-mutated captures.
