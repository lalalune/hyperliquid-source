# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d444c0–0x4d4459b` (219 bytes)
- `.eh_frame` FDE VA: `0x12f2820`

The verifier checks the target digest, exact FDE row, 20 complete instruction-byte
witnesses, and two one-byte mutations that must be rejected. This is bounded
static provenance, not an execution or security assessment.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The 0x8000000000000000 input-qword path writes leading qword 0 and calls 0x4df4ca0. For first qword 0x8000000000000002 the next input qword selects three payload paths. Zero uses the two-lane unpack, subtract and add sequence with .rodata biases 2^52 and 2^84 to convert the unsigned 64-bit payload. When the next qword is nonzero and its low 32 bits equal 1, cvtsi2sdq converts the signed payload. The other selected path copies the 64-bit payload through XMM0. All three write the floating-point payload at result +8 and leading qword 1. A separate helper path stores leading qword 2.
