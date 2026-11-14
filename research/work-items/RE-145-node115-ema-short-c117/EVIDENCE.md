# Evidence

Target `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
FDE `0x4d45070–0x4d4514f` (223 bytes), `.eh_frame` FDE VA `0xf18524`.
The static verifier checks the exact row, 16 complete instruction witnesses, and two rejected in-memory mutations.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The fallback passes the four-byte .rodata slice Date to 0x47b2390. Its tag-9 arm copies a 32-bit field to output +4. The input-byte 0xc0 branch sets that field to zero. Both write byte 9 at +0. Other fallback tags take a 32-byte copy.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-145-node115-ema-short-c117/verify.py`
