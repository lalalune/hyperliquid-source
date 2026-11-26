# RE-001: node115 sibling return-tag family c142–c149

This packet answers one bounded #115 function-map question: do the eight adjacent FDEs after c141 form one statically consistent helper family, and what terminal result-store forms are directly visible in the artifact?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d46440–0x4d464be`, `0x4d464c0–0x4d46533`, `0x4d46540–0x4d465c4`, `0x4d465d0–0x4d4664e`, `0x4d46650–0x4d466d4`, `0x4d466e0–0x4d46764`, `0x4d46770–0x4d467ee`, `0x4d467f0–0x4d46863`
- `.eh_frame` FDE file offsets: `0xf18960`, `0xf18980`, `0xf189a0`, `0xf189c0`, `0xf189e0`, `0xf18a00`, `0xf18a20`, `0xf18a40`

Observed static facts:

- all eight entries have the same prologue shape, one direct call to `0x4892290`, and an `rbx` return pointer;
- six entries write a terminal value through `(%rbx)`: immediate `1`, immediate `2`, or the literal `0x8000000000000001`; two return the pointer without a terminal store;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these eight FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c142-c149/verify.py
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
