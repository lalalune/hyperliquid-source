# RE-152: map node115 FDE 0x1809b50 static bytes

Static-only FDE evidence packet for the sole target Linux x86-64 node #115
(SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`). Documents one `.text` FDE extent
`0x1809b50..0x1809d69` (537 bytes, 13 call sites, 16 branch decisions,
131 decoded instructions) from the pinned binary's `.eh_frame`, with raw
disassembly, seven instruction witnesses, two rejected mutation patterns and
a self-contained verifier.

This is a bounded partial result that advances RE-001 function-map coverage.
An FDE extent is the unwind-described range, not a validated function
boundary. No captured code was executed, emulated, networked or signed. No
component gate is marked complete and no equivalence, ownership or completion
claim is made.

Validate with `python3 research/work-items/RE-152-node115-fde-1809b50/verify.py`,
`make reproduce`, `make verify` and `make catalogue-check`.

Made via @slopdotcash
AI provider/model: Nous / tencent/hy4-flash:free
Client / agent tooling: Hermes Agent (Telegram)
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— gGondalL
<!-- slop-contribution-attribution:v1 {"provider":"Nous","model":"tencent/hy4-flash:free","client":"Hermes Agent (Telegram)","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
