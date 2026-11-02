# Node94 population count and u32 field projection

`count_bits(u64) -> u32` reconstructs the complete unwindless body at ELF VA
`0x5660010..0x5660072` using safe fixed-width lane reductions. It returns 0..64.
`count_field(u32) -> u32` covers the zero-extended dword input loaded by its
complete caller at `0x4f9eb90..0x4f9eba5`; it returns 0..32.

This dependency-free `no_std` component builds directly with rustc 1.94.1.
The input-only client reads little-endian u64 words and emits two little-endian
u32 values: the full word's count and its low u32 field's count. It rejects
partial input before output. This protocol is a new validation interface,
not the original ABI.

[Evidence and reproduction](../../research/work-items/RE-004-popcount-rust-94/README.md)
include complete byte/boundary qualification, the all-domain lane proof,
pre-Rust independent textual-bit expectations and real native builds with
observable wrong variants. No captured executable or instruction emulator runs.
