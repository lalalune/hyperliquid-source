# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d45640–0x4d45728` (232 bytes), `.eh_frame` file offset `0xf1865c`
- Distinct observations: byte-state reads at `+0x20/+0x21`, empty-state zero writer, helper argument `4`, split stores at `+0x04/+0x0c`, and tag-9 publication.
- Negative controls: entry and tag-writer mutations are rejected; no captured code is executed or emulated.
