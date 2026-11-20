# RE-001: node115 sibling return-tag family c166–c173

This packet answers one bounded #115 function-map question: what terminal result-store forms are statically visible in the next eight adjacent FDEs after the c158–c165 family, and do their call edges and unwind boundaries agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d470d0–0x4d47154`, `0x4d47160–0x4d471e4`, `0x4d471f0–0x4d47274`, `0x4d47280–0x4d472fe`, `0x4d47300–0x4d47373`, `0x4d47380–0x4d473f3`, `0x4d47400–0x4d47484`, `0x4d47490–0x4d47503`
- `.eh_frame` FDE file offsets: `0xf18c60`, `0xf18c80`, `0xf18ca0`, `0xf18cc0`, `0xf18ce0`, `0xf18d00`, `0xf18d20`, `0xf18d40`

Observed static facts:

- all eight entries have the same prologue shape and one direct call to `0x4892290` before their terminal path;
- four entries copy `rax` into `(%rbx)`, one writes zero to `0x8(%rbx)`, and three return the `rbx` pointer without a result-store;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these eight FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c166-c173/verify.py
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
