# Evidence

- Artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Start/end: `0x4d3f3a0–0x4d3f4b0` (272 bytes)
- FDE `.eh_frame` offset: `0xf17c40`
- Identity controls: six instruction-byte witnesses and two mutation checks.

The verifier compares the repository FDE extractor with GNU objdump output and
rejects entry and internal-call mutations. It is static-only and requires no
network, credentials, or live deployment.
