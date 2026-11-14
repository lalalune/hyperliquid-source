# Evidence

Target `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
FDE `0x4d44ae0–0x4d44bc5` (229 bytes), `.eh_frame` FDE VA `0xf183e4`.
Static verifier checks the exact row, 14 complete instruction witnesses, and two rejected in-memory mutations.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The input-byte 0xc0 branch writes leading qword zero and 0x8000000000000000 at output +8. Fallback calls 0x4bef5b0 with EDX=0 and copies its 40-byte result as a qword and two 16-byte stores.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-139-node115-ema-short-c111/verify.py`
