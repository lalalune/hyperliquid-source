# RE-001: node115 sibling return-tag family c203–c206

This packet answers one bounded #115 function-map question: what terminal forms are statically visible in the four adjacent `0x9` byte-tag FDEs after c198–c202, and do their unwind boundaries and direct call edges agree?

Target and coordinates:

- artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- section: `.text`, Linux x86-64 node #115
- FDE ranges: `0x4d48620–0x4d48689`, `0x4d48690–0x4d48704`, `0x4d48710–0x4d48779`, `0x4d48780–0x4d487fa`
- `.eh_frame` FDE file offsets: `0xf19140`, `0xf19160`, `0xf19180`, `0xf191a0`

Observed static facts:

- all four entries use the same `0x9` byte-tag prologue shape and one direct call to `0x4892290` before their terminal path;
- two entries return the `rbx` pointer without a result-store, one writes immediate result `3`, and one stores a call-derived value through `rax` into `(%rbx)`;
- the disjoint `int3` gaps and shifted-range negative control are preserved; no bytes are transplanted or executed.

These are observations, not source-level names or semantic equivalence. The packet does not claim component ownership, runtime behavior, or a complete family inventory beyond these four FDEs.

Reproduction from the repository root:

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c203-c206/verify.py
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
