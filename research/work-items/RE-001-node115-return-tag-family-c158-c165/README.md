# RE-001: node115 sibling return-tag family c158–c165

This packet answers one bounded #115 function-map question: what terminal result-store forms are statically visible in the next eight adjacent FDEs after the c150–c157 family, and do their call edges and unwind boundaries agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d46ca0–0x4d46d1e`, `0x4d46d20–0x4d46d93`, `0x4d46da0–0x4d46e13`, `0x4d46e20–0x4d46e9e`, `0x4d46ea0–0x4d46f1e`, `0x4d46f20–0x4d46fa4`, `0x4d46fb0–0x4d47034`, `0x4d47040–0x4d470c4`
- `.eh_frame` FDE file offsets: `0xf18b60`, `0xf18b80`, `0xf18ba0`, `0xf18bc0`, `0xf18be0`, `0xf18c00`, `0xf18c20`, `0xf18c40`

Observed static facts:

- all eight entries have the same prologue shape and one direct call to `0x4892290` before their terminal path;
- three entries write immediate result `1`, one writes immediate result `3`, three copy `rax` into `(%rbx)`, and two return the `rbx` pointer without a result-store;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these eight FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c158-c165/verify.py
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
