# Evidence

- Artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Start: `0x4d3f290`
- Exclusive end: `0x4d3f39d`
- Extent: `269` bytes
- FDE row: `0x4d3f290 0x4d3f39d 269 .text 0xf17c10`
- Independent identity controls: five instruction-byte witnesses, plus a
  mutated entry witness and a mutated internal call-site witness.

The verifier uses GNU `objdump` and the repository FDE extractor, and rejects
both boundary or witness mutations. No runtime, network, credential, or live
deployment interaction is required.
