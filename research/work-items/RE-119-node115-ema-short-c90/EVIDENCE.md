# RE-119: node115 EMA short c90

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43510–0x4d436a9` (409 bytes), `.eh_frame` FDE VA `0xf18060`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 15 instruction witnesses, and two negative controls. The selected instructions show the bounded scan, cursor update, marker write, fallback call, and return as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected scan compares ordered ASCII n, u, l, l and writes byte 0 to result +1 at 0x4d435ef. A separate call to 0x525f7d0 at 0x4d43629 is followed by a return-value comparison to 1. The equal branch stores RDX to result +8. The unequal branch copies the local output record and writes byte 1 to result +1 at 0x4d43661.
