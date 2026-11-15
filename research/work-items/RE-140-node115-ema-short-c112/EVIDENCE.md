# Evidence

Target `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
FDE `0x4d44bd0–0x4d44cba` (234 bytes), `.eh_frame` FDE VA `0xf18418`.
The static verifier checks the exact row, 17 complete instruction witnesses, and two rejected in-memory mutations.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The fallback passes the three-byte .rodata slice Ntl to 0x479a870. A local tag 9 produces byte 9 at output +0, qword 1 at +8 and the local payload qword at +0x10. The input-byte 0xc0 branch writes byte 9 and qword 0 at +8. The other fallback result takes a 32-byte copy.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-140-node115-ema-short-c112/verify.py`
