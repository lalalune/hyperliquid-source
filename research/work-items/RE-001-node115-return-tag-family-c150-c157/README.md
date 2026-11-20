# RE-001: node115 sibling return-tag family c150–c157

This packet answers one bounded #115 function-map question: what terminal result-store forms are statically visible in the next eight adjacent FDEs after the c142–c149 family, and do their call edges and unwind boundaries agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d46870–0x4d468f4`, `0x4d46900–0x4d4697a`, `0x4d46980–0x4d46a04`, `0x4d46a10–0x4d46a8e`, `0x4d46a90–0x4d46b03`, `0x4d46b10–0x4d46b83`, `0x4d46b90–0x4d46c03`, `0x4d46c10–0x4d46c94`
- `.eh_frame` FDE file offsets: `0xf18a60`, `0xf18a80`, `0xf18aa0`, `0xf18ac0`, `0xf18ae0`, `0xf18b00`, `0xf18b20`, `0xf18b40`

Observed static facts:

- all eight entries have the same prologue shape and one direct call to `0x4892290` before their terminal path;
- four entries write a result (`0x8000000000000001`, `0`, `0x8000000000000000`, or `2`), three return the `rbx` pointer without a result-store, and one copies `rax` into `(%rbx)`;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these eight FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c150-c157/verify.py
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
