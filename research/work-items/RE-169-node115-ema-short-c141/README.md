# RE-169: map node115 EMA short c141

This contribution records one bounded, reviewable static mapping for the supplied node115 artifact:

- `.text` packet: `0x4d463c0–0x4d4643e` (126 bytes, end-exclusive)
- `.eh_frame` FDE file offset: `0xf18940`
- unwind index entry: `0x4d463c0 -> 0xf18940`
- artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

The packet is documented as static evidence only. The disassembly excerpt and verifier bind the exact bytes, FDE extent, unwind-index entry, and artifact digest. This does not claim source-level semantics, component ownership, runtime behavior, or equivalence to another implementation.

Validation from the repository root:

```sh
python3 research/work-items/RE-169-node115-ema-short-c141/verify.py
PATH=/opt/homebrew/opt/binutils/bin:$PATH make reproduce
PATH=/opt/homebrew/opt/binutils/bin:$PATH make verify
PATH=/opt/homebrew/opt/binutils/bin:$PATH make catalogue-check
```

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
