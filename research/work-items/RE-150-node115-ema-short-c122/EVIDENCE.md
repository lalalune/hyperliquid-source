# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d45550–0x4d45637` (231 bytes), `.eh_frame` file offset `0xf18620`
- Distinct observations: empty-state tag-9 path, helper call at `0x4d455f3`, compact tag `0x0109` publication and a separate wide fallback copy.
- Negative controls: entry and compact-tag mutations are rejected; no captured code is executed or emulated.
