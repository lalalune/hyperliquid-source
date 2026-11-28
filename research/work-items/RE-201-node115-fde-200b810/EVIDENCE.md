# Evidence: node115 FDE 0x200b810

- Task: RE-201 - bounded static FDE byte map, node #115
- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x200b810..0x200b9da` (459 bytes), `.text`; FDE record `0x10cf3a4`
- Coordinate system: ELF virtual addresses; bytes were read-only. No captured code was executed or emulated.
- Static excerpt: `excerpts.objdump.txt`
- Verifier: `verify.py` recomputes the binary digest, re-derives the FDE and unwind entry from the ELF, and checks 7 exact byte witnesses plus 2 mutation negatives.
- Limits: an FDE extent is an unwind-described range, not a validated function boundary. No source-level semantics, ownership, equivalence or gate completion is claimed.
