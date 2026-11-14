# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d3dcd0–0x4d3ddd9` (265 bytes), `.eh_frame` offset `0xf17794`
- Witnesses: stack record initialization at `0x4d3dd0d–0x4d3dd7c`; repeated helper calls at `0x4d3dd90`, `0x4d3dda2`, and `0x4d3ddba`; scalar compare at `0x4d3ddac`.
- Controls: verifier rejects target-hash, FDE-boundary, byte-partition, witness, and identity-mutation mismatches.

No execution, emulation, or behavioral equivalence claim is made.
