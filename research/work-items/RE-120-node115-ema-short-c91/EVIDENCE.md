# RE-120: node115 EMA short c91

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d436b0–0x4d4379a` (234 bytes), `.eh_frame` file offset `0xf18084`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor/count updates, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.
