# RE-001: node115 sibling return-tag family c207–c211

Bounded RE-001 static packet for the five adjacent `0x9` byte-tag FDEs covering `0x4d48800–0x4d48a39`.

- Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE offsets: `0xf191c0`, `0xf191e0`, `0xf19200`, `0xf19220`, `0xf19240`
- Each entry has one direct call before its terminal path; c207–c210 target `0x4892290`, while c211 targets `0x4892260`. Four return `rbx`, one writes immediate result `1` to `(%rbx)`.
- Static observation only; no binary execution or source-level equivalence is claimed.

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c207-c211/verify.py
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
