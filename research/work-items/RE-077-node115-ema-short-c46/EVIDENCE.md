# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3d600, 0x4d3d8d2)`, 722 bytes
- `.eh_frame` offset: `0xf1767c`
- Witnesses cover sentinel checks at `+0x10/+0x28`, repeated comparator calls, and common early-exit branches.
- Identity controls reject truncated and first-byte-mutated captures.
