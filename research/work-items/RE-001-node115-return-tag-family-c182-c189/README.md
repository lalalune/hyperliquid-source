# RE-001: node115 sibling return-tag family c182–c189

This packet answers one bounded #115 function-map question: what terminal result-store forms are statically visible in the next eight adjacent FDEs after c174–c181, and do their call edges and unwind boundaries agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d47940–0x4d479c4`, `0x4d479d0–0x4d47a43`, `0x4d47a50–0x4d47ac3`, `0x4d47ad0–0x4d47b43`, `0x4d47b50–0x4d47bce`, `0x4d47bd0–0x4d47c54`, `0x4d47c60–0x4d47cd3`, `0x4d47ce0–0x4d47d64`
- `.eh_frame` FDE file offsets: `0xf18e60`, `0xf18e80`, `0xf18ea0`, `0xf18ec0`, `0xf18ee0`, `0xf18f00`, `0xf18f20`, `0xf18f40`

Observed static facts:

- all eight entries have the same prologue shape and one direct call to `0x4892290` before their terminal path;
- three entries return the `rbx` pointer without a result-store, three store `rax` or its immediate-derived value into `(%rbx)`, and one writes immediate result `1`;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these eight FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c182-c189/verify.py
PATH=/opt/homebrew/opt/binutils/bin:$PATH make doctor
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
