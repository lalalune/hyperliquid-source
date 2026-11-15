# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d45240–0x4d45326` (230 bytes), `.eh_frame` file offset `0xf1858c`
- Distinct observations: byte-state reads at offsets `0x20/0x21`, a zero-state writer at `+0x40`, a nine-byte helper argument, and terminal tag-9 publication at `0x4d45301`.
- Negative controls: mutation of the entry byte and terminal tag writer is rejected; no captured code is executed or emulated.
