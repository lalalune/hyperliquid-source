# Evidence

- Task: RE-153 - bounded static FDE byte map, node #115
- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x1806f40..0x180713f` (511 bytes), `.text`
- FDE record: `fde_va=0x108689c cie_va=0x103d604 lsda_va=0x1a37a4 unwind_index=8766`
- Coordinate system: ELF virtual addresses; bytes were read-only. No captured code was executed or emulated.
- Toolchain: objdump (binutils) disassembly with explicit `--start-address`/`--stop-address`; `tools/fde_extents.py` for the `.eh_frame` extent.
- Static observations: 127 decoded instructions, 9 call sites, 16 branch instructions. One observed direct call target is `0x17fbb40` (shared with the RE-152 extent at a different call site).
- Independent checks: 7 instruction witnesses, 2 rejected mutation patterns, digest recheck and FDE re-derivation from the ELF.
- Negative controls: a NOP-filled call site and a zeroed immediate are rejected.
- Limitations: unwind extent, not a validated function boundary; no equivalence, ownership or completion claim; no component gate marked complete.
