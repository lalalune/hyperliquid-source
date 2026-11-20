# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d45460–0x4d4554a` (234 bytes), `.eh_frame` file offset `0xf185ec`
- Distinct observations: byte-state reads at `+0x20/+0x21`, zero-state writer at the empty branch, helper argument `5`, and tag-9 publication with a wide fallback copy.
- Negative controls: entry and tag-writer mutations are rejected; no captured code is executed or emulated.
