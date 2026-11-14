# RE-122: node115 EMA short c93

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43930–0x4d43a3c` (268 bytes), `.eh_frame` file offset `0xf180e4`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, marker write, fallback call, and return sequence as direct disassembly observations.
