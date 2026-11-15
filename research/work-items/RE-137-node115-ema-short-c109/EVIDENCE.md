# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d44870–0x4d44988` (280 bytes)
- `.eh_frame` FDE VA: `0xf18384`

The verifier checks the exact FDE row, 17 instruction witnesses, and two
rejected in-memory mutations. It does not execute captured bytes or claim runtime behavior.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The input-byte 0xc0 branch clears a dword at output +0x48 and sets the leading qword to zero. Fallback at 0x4d44926 passes EDX=0 to 0x48c18d0. The caller tests a dword at local result +0x40 and copies either 72 bytes with leading tag 0 (nonzero) or 32 bytes with leading tag 1 (zero) to the output starting at +8.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-137-node115-ema-short-c109/verify.py`
