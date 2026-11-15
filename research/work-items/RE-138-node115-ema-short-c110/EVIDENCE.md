# Evidence

Target `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
FDE `0x4d44990–0x4d44ae0` (336 bytes), `.eh_frame` FDE VA `0xf183b8`.
Verifier checks the exact row, 23 complete instruction witnesses, and two rejected in-memory mutations; no captured bytes execute.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected n/u/l/l path stores leading qword 0x8000000000000001. After the call to 0x4daad30, the caller compares the local result with that value. On equality it copies a qword to output +8 and increments the leading value to 0x8000000000000002. Otherwise it copies 32 bytes from the fallback. Selected short and mismatching scan exits stage 5 and 9, respectively, for the separate call to 0x525a6a0.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-138-node115-ema-short-c110/verify.py`
