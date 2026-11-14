# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d441e0–0x4d442d2` (242 bytes)
- `.eh_frame` FDE VA: `0xf18290`

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

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The 0xc0 input path writes word 0x0309 at result +0. The selected fallback passes the 19-byte .rodata slice ReferenceOracleMode, a length of 19 in ECX, and value 3 in R9D to 0x478d440. A local result tag of 9 causes the next local byte to be copied to result +1 before writing tag 9.
