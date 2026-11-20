# RE-001: node #115 return-tag sibling family c242-c245

This packet records a bounded static observation against the pinned node #115
binary. Four adjacent FDEs (`0xf19640`, `0xf19660`, `0xf19680`, `0xf196a0`)
share the same constructor-like helper call. Siblings c242 and c243 write the
constant `0x8000000000000000` to `[rbx]` before returning; c244 and c245 return
the original `rbx` object without that store. The claim is limited to the
recorded instruction bytes and unwind extents.

Target: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The binary was not executed or emulated, no source name is inferred, and no
caller reachability is claimed.

Reproduce with `python3 verify.py`. The repository-level checks used for this
packet are `make doctor`, `make reproduce`, `make verify`, and
`make catalogue-check`.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]

<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
