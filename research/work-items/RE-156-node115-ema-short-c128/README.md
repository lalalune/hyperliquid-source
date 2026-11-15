# RE-156: node115 EMA short c128

This contribution records the next independently bounded `.text` FDE in the
pinned `artifacts/node/115/hl-node` binary:

- range `0x4d45b50–0x4d45c3a` (234 bytes)
- `.eh_frame` FDE file offset `0xf18768`
- target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

The packet contains an objdump excerpt, target digest and FDE membership
checks, seven positive byte witnesses, and two negative mutation checks. It is
static evidence only; no execution or emulation is claimed.

Validation:

```text
python3 research/work-items/RE-156-node115-ema-short-c128/verify.py
git submodule update --init --recursive
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
