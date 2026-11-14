# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3b5c0, 0x4d3b7b8)`, 504 bytes
- `.eh_frame` offset: `0xf1725c`
- Static observations: indirect comparison at `+0x1b`, sentinel checks at fields `+0x00`, `+0x10`, `+0x65`, `+0x66`, `+0x64`, and `+0x67`, with common early-return target `0x4d3b5f3`
- Controls: artifact identity mutations and per-witness byte mutations are rejected

No captured binary code is executed or emulated.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3b5c0` include `0x4d3c3d9` (`0x4d3bbe0` FDE, jmp).
