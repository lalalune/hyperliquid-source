# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3b7c0, 0x4d3bb11)`, 849 bytes
- `.eh_frame` offset: `0xf17298`
- Static witnesses cover the tag normalization prologue, big-endian payload comparisons, three indirect comparator calls, and common result jumps.
- Controls reject truncated and first-byte-mutated artifact captures.

No captured binary code is executed or emulated.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3b7c0` include `0x4d3bfae` (`0x4d3bbe0` FDE, call).
