# RE-001: node #115 return-tag sibling family c250-c253

This packet records four adjacent FDE-described siblings in the pinned node
#115 image. Each calls the same helper and returns the original `rbx` object.
c250 stores `0x8000000000000000` to `[rbx]`, c251 stores
`0x8000000000000001`, while c252 has no terminal field store and c253 stores
the literal `1`. The claim is limited to the recorded instruction bytes and
unwind extents.

Target: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Static ELF evidence only: the binary was not executed or emulated, no source
name is inferred, and no caller reachability is claimed.

Reproduce with `python3 verify.py`; repository checks used were `make doctor`,
`make reproduce`, `make verify`, and `make catalogue-check`.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]

<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
