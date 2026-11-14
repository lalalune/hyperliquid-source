# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d43fd0–0x4d440dc` (268 bytes)
- `.eh_frame` FDE VA: `0x12f27e8`

The verifier checks the target digest, exact FDE row, 18 complete instruction-byte
witnesses, and two one-byte mutations that must be rejected. This is bounded
static provenance, not an execution or security assessment.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Negating the first input qword selects the overflow arm only for 0x8000000000000000. That arm writes leading qword 0 and calls 0x4df4ca0. The 0x8000000000000002 path examines the second input qword and, for selected cases, copies the third input qword to result +8 with leading qword 1. The two selected alternate calls use distinct R_X86_64_RELATIVE slots, 0x64e0910 to 0x5c54c30 and 0x64e0900 to 0x5c54bd0. Each stores its returned qword at result +8 with leading qword 2.
