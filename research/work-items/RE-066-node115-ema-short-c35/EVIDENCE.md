# Evidence

- Artifact: `artifacts/node/115/hl-node`
- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Coordinate system: ELF virtual addresses, no masks
- FDE: `[0x4d3b4d0, 0x4d3b5b1)`, 225 bytes
- `.eh_frame` offset: `0xf17230`
- Witnesses: prologue, four load/subtract/cmov/call groups, three early exits, final result arithmetic
- Controls: full-artifact hash rejection, first-byte mutation rejection, semantic-anchor mutation rejection

All observations are static disassembly and unwind metadata. No captured code is executed or emulated.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3b4d0` include `0x4d3b21d` (`0x4d3ae00` FDE, call).
