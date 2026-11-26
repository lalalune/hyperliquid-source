# RE-001: node115 sibling return-tag family c212–c217

Bounded static packet for six adjacent `0x9` byte-tag FDEs (`0x4d48a40–0x4d48d00`). Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

All six contain one direct call to `0x4892290`; c212, c214, c215, c216 return `rbx`, c213 stores a call-derived value, and c217 writes immediate zero at `0x24(%rbx)`. Static observations only.

```sh
python3 research/work-items/RE-001-node115-return-tag-family-c212-c217/verify.py
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
