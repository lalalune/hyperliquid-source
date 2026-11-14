# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3bb20, 0x4d3bbe0)`, 192 bytes
- `.eh_frame` offset: `0xf172d4`
- Witnesses cover tag tests, null-pointer branches, optional `+0x08/+0x18` comparisons, and the final `+0x20` scalar comparison.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3bb20` include `0x4d3c2b0` (`0x4d3bbe0` FDE, jmp).
