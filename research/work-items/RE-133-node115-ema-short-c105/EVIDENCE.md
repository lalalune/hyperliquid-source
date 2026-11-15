# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d443d0–0x4d444b6` (230 bytes)
- `.eh_frame` FDE VA: `0xf18300`

The verifier checks the target digest, exact FDE row, 14 complete instruction-byte
witnesses, and two one-byte mutations that must be rejected. This is bounded
static provenance, not an execution or security assessment.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The fallback passes the exact 12-byte .rodata slice PriorityRate in RDX and length 12 in ECX to 0x479b490. Tag 9 selects a 32-bit discriminator of 1 at result +4 and a 32-bit payload at result +8. The input-0xc0 path writes a 32-bit discriminator of 0 at result +4. Both paths write byte 9 at result +0.
