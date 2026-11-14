# RE-119: node115 EMA short c90

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43510–0x4d436a9` (409 bytes), `.eh_frame` file offset `0xf18060`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. The selected instructions show the bounded scan, cursor update, marker write, fallback call, and return as direct disassembly observations.
