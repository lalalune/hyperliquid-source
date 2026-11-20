# RE-001: node115 sibling return-tag family c190–c192

This packet answers one bounded #115 function-map question: what terminal result-store forms are statically visible in the final three adjacent FDEs of the c182–c192 sibling run before the next structural transition, and do their call edges and unwind boundaries agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d47e80–0x4d47ef3`, `0x4d47f00–0x4d47f73`, `0x4d47f80–0x4d48004`
- `.eh_frame` FDE file offsets: `0xf18fa0`, `0xf18fc0`, `0xf18fe0`

Observed static facts:

- all three entries have the same compact prologue and one direct call to `0x4892290` before their terminal path;
- two entries return the `rbx` pointer without a result-store, while one stores the call result through `rax` into `(%rbx)`;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these three FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c190-c192/verify.py
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
