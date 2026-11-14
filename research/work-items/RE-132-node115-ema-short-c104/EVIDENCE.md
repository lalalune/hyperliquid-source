# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d442e0–0x4d443ca` (234 bytes)
- `.eh_frame` FDE VA: `0xf182cc`

The verifier checks the target digest, exact FDE row, 12 complete instruction-byte
witnesses, and two one-byte mutations that must be rejected. This is bounded
static provenance, not an execution or security assessment.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The fallback passes the exact three-byte .rodata slice Ltv in RDX, with length 3 in ECX, to 0x479c710. A local tag 9 selects qword 1 at result +8 and the local +8 qword at result +0x10. The input marker path selects qword 0 at result +8, and both paths write byte 9 at result +0.
