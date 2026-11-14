# Evidence

Target `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
FDE `0x4d44f80–0x4d45066` (230 bytes), `.eh_frame` FDE VA `0xf184f0`.
The static verifier checks the exact row, 18 complete instruction witnesses, and two rejected in-memory mutations.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]
<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The fallback sets input byte +0x20 to 1 and zero-extends two byte arguments. Its indirect call resolves through RELATIVE slot 0x64e2580 to 0x348e980 in the pinned ELF. The tag-9 arm writes byte 9 with qword 1 at +8 and the returned qword at +0x10. The input-byte 0xc0 arm writes byte 9 and qword 0 at +8. Other local tags copy 32 bytes.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-144-node115-ema-short-c116/verify.py`
