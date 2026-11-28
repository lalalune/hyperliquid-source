# Evidence: node115 FDE 0x200df20

- Task: RE-202 - bounded static FDE byte map, node #115
- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x200df20..0x200e0b0` (401 bytes), `.text`; FDE record `0x10cfa10`
- Coordinate system: ELF virtual addresses; bytes were read-only. No captured code was executed or emulated.
- Static excerpt: `excerpts.objdump.txt`
- Verifier: `verify.py` recomputes the binary digest, re-derives the FDE and unwind entry from the ELF, and checks 7 exact byte witnesses plus 2 mutation negatives.
- Limits: an FDE extent is an unwind-described range, not a validated function boundary. No source-level semantics, ownership, equivalence or gate completion is claimed.
