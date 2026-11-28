# RE-200: static FDE byte map for node115 0x2009b20

Static-only evidence packet for the sole target Linux x86-64 node #115 (SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Adds a bounded witness set for one `.text` FDE extent (0x2009b20..0x2009c17, 248 bytes, FDE 0x10cee6c)
with raw disassembly, 7 byte witnesses, two mutation negatives and a self-contained
digest-bound verifier. No captured code was executed, emulated, networked or signed.

## Failing-first regression check

Before this packet, `python3 research/work-items/RE-200-node115-fde-2009b20/verify.py` exits 1 because the
witness set does not exist (the FDE has no committed packet). With this PR the same
command exits 0 and prints the verification result.

Made via @slopdotcash
AI provider/model: Nous / tencent/hy4-flash:free
Client / agent tooling: Hermes Agent (subagent)
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— gGondalL
<!-- slop-contribution-attribution:v1 {"provider":"Nous","model":"tencent/hy4-flash:free","client":"Hermes Agent (subagent)","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
