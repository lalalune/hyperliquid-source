# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d43ee0–0x4d43fca` (234 bytes)
- `.eh_frame` FDE VA: `0xf18214`

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

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected marker path writes qword 0x8000000000000000 at result +8 and joins the byte-9 store. The fallback at 0x4d43f88 supplies EDX=1 to 0x4a9b140. When the local result tag is 9 it copies 24 bytes from local +8 to result +8 before the tag write.
