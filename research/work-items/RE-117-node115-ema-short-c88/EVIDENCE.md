# RE-117: node115 EMA short c88

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43340–0x4d4341c` (220 bytes), `.eh_frame` file offset `0xf17ff0`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. The selected instructions show state-byte initialization, cursor/count updates, the marker write, the fallback call, and the return sequence as direct disassembly observations.
