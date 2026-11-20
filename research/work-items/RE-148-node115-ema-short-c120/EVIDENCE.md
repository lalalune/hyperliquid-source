# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d45330–0x4d4545b` (299 bytes), `.eh_frame` file offset `0xf185c0`
- Distinct observations: R14/RBX prologue, 0x88-byte stack frame, helper result discriminator at `rsp+8`, and tag-1/tag-2 publication paths.
- Negative controls: entry-prologue and empty-state writer mutations are rejected; no captured code is executed or emulated.
