# RE-001: node #115 return-tag sibling family c262-c265

This packet records four adjacent FDE-described siblings in the pinned node
#115 image. Each calls the same helper and returns the original `rbx` object.
c262 and c263 have plain terminal returns, c264 writes literal `1` at `[rbx]`,
and c265 writes literal `0` at `[rbx+8]` before the return. The claim is
limited to the instruction bytes and unwind extents.

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
