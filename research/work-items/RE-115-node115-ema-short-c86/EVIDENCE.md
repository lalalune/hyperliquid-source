# RE-115: node115 EMA short c86

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43130–0x4d43233` (259 bytes), `.eh_frame` file offset `0xf17f88`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. The selected instructions show initialization of the state byte at `0x20(%rsi)`, cursor/count updates, a call-based fallback, and the final output stores. These are direct disassembly observations.
