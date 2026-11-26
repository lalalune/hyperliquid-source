# RE-001: node115 sibling return-tag family c193–c197

This packet answers one bounded #115 function-map question: what terminal forms are statically visible in the five adjacent FDEs immediately after c190–c192, and do their unwind boundaries and direct call edges agree across the prologue-shape transition?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d480e0–0x4d48149`, `0x4d48150–0x4d481b9`, `0x4d481c0–0x4d48229`, `0x4d48230–0x4d48299`, `0x4d482a0–0x4d48309`
- `.eh_frame` FDE file offsets: `0xf19000`, `0xf19020`, `0xf19040`, `0xf19060`, `0xf19080`

Observed static facts:

- all five entries use the same `0x9` byte-tag prologue shape and one direct call to `0x4892290` before their terminal path;
- all five return the `rbx` pointer without a result-store in the bounded excerpt;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these five FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c193-c197/verify.py
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
