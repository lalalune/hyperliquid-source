# RE-097: node115 EMA short c68

Static ELF/FDE evidence for the independently bounded `0x4d3f3a0–0x4d3f4b0`
function in the pinned node-115 artifact. This packet does not claim source
reconstruction or runtime equivalence.

## Validation

```text
python3 research/work-items/RE-097-node115-ema-short-c68/verify.py
git submodule update --init --recursive
make reproduce
make verify
make catalogue-check
```

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
