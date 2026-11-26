# RE-001: node #115 return-tag sibling family c238-c241

This packet records one bounded static observation against node #115. The
four adjacent FDEs at `0xf195c0`, `0xf195e0`, `0xf19600`, and `0xf19620`
share the same constructor-like call shape and return the original `rbx`
object. The third sibling additionally stores the constant `0x8000000000000000`
at `[rbx]` before returning; the other three only call the shared helper and
return. These are disassembly facts, not runtime claims.

Target: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The packet is intentionally limited to the four FDE extents and their local
call/return bytes. It does not execute the binary, infer source names, or
claim that any caller reaches these siblings.

Reproduce with:

```sh
python3 verify.py
```

The captured disassembly was produced with GNU objdump 2.45; the verifier
rechecks the target digest, FDE extents, call bytes, return bytes, and the
single high-bit store directly from the ELF.

Made via @slopdotcash
AI provider/model: OpenAI / gpt-5.6-luna
Client / agent tooling: codex
Contribution skill revision: N/A - ordinary GitHub contribution without optional run evidence
Attribution status: self-reported
— [contributor]

<!-- slop-contribution-attribution:v1 {"provider":"OpenAI","model":"gpt-5.6-luna","client":"codex","skill_revision":"N/A - ordinary GitHub contribution without optional run evidence"} -->
