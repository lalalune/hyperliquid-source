# RE-126: node115 EMA short c97

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43d00–0x4d43de2` (226 bytes), `.eh_frame` file offset `0xf181ac`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.
