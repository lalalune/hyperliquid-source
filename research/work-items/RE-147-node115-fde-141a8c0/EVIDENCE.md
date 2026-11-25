# Evidence

- Task: RE-147 - bounded static FDE byte map, node #115
- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x141a8c0..0x141a9f7` (311 bytes), `.text`
- Coordinate system: ELF virtual addresses; bytes were read-only. No captured code was executed or emulated.
- Independent checks: 7 instruction witnesses and 2 rejected mutation patterns over the pinned FDE; `verify.py` recomputes the binary digest and the FDE extent from the ELF.
