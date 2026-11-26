# RE-001: node115 sibling return-tag family c218–c223

Bounded static packet for six adjacent `0x9` byte-tag FDEs covering `0x4d48d00–0x4d48f99`.

- Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE offsets: `0xf19320` through `0xf193c0`
- Each extent has one direct call to `0x4892290` and returns `rbx` without a result-store.
- Static observations only; no binary execution or source-level equivalence is claimed.

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c218-c223/verify.py
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
