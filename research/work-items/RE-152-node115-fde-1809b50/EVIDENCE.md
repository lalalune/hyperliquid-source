# Evidence

- Task: RE-152 - bounded static FDE byte map, node #115
- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x1809b50..0x1809d69` (537 bytes), `.text`
- FDE record: `fde_va=0x10869e4 cie_va=0x103d604 lsda_va=0x1a38cc unwind_index=8781`
- Coordinate system: ELF virtual addresses; bytes were read-only. No captured code was executed or emulated.
- Toolchain: objdump (binutils) disassembly with `--start-address`/`--stop-address`; `tools/fde_extents.py` for the `.eh_frame` extent.
- Static observations: 131 decoded instructions, 13 call sites, 16 conditional/unconditional branch instructions.
- Independent checks: 7 instruction witnesses and 2 rejected mutation patterns over the pinned FDE; `verify.py` recomputes the binary digest and re-derives the FDE extent from the ELF.
- Negative controls: a NOP-filled call site and a zero-filled immediate are rejected.
- Limitations: unwind extent, not a validated function boundary; no equivalence, ownership or completion claim; no component gate is marked complete.
