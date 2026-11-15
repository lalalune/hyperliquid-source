# RE-001: node115 sibling return-tag family c198–c202

This packet answers one bounded #115 function-map question: what terminal forms are statically visible in the five adjacent `0x9` byte-tag FDEs after c193–c197, and do their unwind boundaries and direct call edges agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d483d0–0x4d48439`, `0x4d48440–0x4d484a9`, `0x4d484b0–0x4d4852a`, `0x4d48530–0x4d48599`, `0x4d485a0–0x4d4861a`
- `.eh_frame` FDE file offsets: `0xf190a0`, `0xf190c0`, `0xf190e0`, `0xf19100`, `0xf19120`

Observed static facts:

- all five entries use the same `0x9` byte-tag prologue shape and one direct call to `0x4892290` before their terminal path;
- three entries return the `rbx` pointer without a result-store, and two store a call-derived value through `rax` into `(%rbx)`;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these five FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c198-c202/verify.py
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
