# RE-001: node115 sibling return-tag family c174–c181

This packet answers one bounded #115 function-map question: what terminal result-store forms are statically visible in the next eight adjacent FDEs after the c166–c173 family, and do their call edges and unwind boundaries agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d47510–0x4d4758e`, `0x4d47590–0x4d47614`, `0x4d47620–0x4d476a4`, `0x4d476b0–0x4d47734`, `0x4d47740–0x4d477be`, `0x4d477c0–0x4d4783e`, `0x4d47840–0x4d478b3`, `0x4d478c0–0x4d4793e`
- `.eh_frame` FDE file offsets: `0xf18d60`, `0xf18d80`, `0xf18da0`, `0xf18dc0`, `0xf18de0`, `0xf18e00`, `0xf18e20`, `0xf18e40`

Observed static facts:

- all eight entries have the same prologue shape and one direct call to `0x4892290` before their terminal path;
- three entries copy `rax` into `(%rbx)`, three write immediate result `2`, two write immediate result `1`, and one returns the `rbx` pointer without a result-store;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these eight FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c174-c181/verify.py
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
