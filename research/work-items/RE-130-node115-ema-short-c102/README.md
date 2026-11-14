# RE-130: node115 EMA short c102

This packet records one exact `.eh_frame` function extent from the pinned node
115 release. It is static evidence only: no captured instruction bytes are
executed and no runtime or vulnerability claim is made.

Validation:

```sh
python3 research/work-items/RE-130-node115-ema-short-c102/verify.py
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
