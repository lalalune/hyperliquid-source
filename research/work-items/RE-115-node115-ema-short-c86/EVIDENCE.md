# RE-115: node115 EMA short c86

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43130–0x4d43233` (259 bytes), FDE VA `0xf17f88`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls. The selected instructions show initialization of the state byte at `0x20(%rsi)`, cursor/count updates, a call-based fallback, and the final output stores. These are direct disassembly observations.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d43130` include `0x4b85429` (`0x4b84f80` FDE, call), `0x4b86680` (`0x4b84f80` FDE, call).
