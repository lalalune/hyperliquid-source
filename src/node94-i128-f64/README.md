# Node94 signed integer to binary64 value projection

`to_binary64_bits(i128) -> u64` implements nearest-even conversion using only
safe integer operations. It reconstructs the low returned bits of node94 ELF
VA `[0x565f4f0,0x565f598)` for every signed 128-bit value, including zero and
`i128::MIN`. The target leaf uses integer instructions, so MXCSR does not
select its rounding rule.

This is a dependency-free `no_std` library compiled directly with rustc 1.94.1,
not a recovered target workspace or original ABI. The input-only validation
client reads little-endian 16-byte words from stdin and emits 8-byte result
words. It rejects a partial input before producing output.

[Evidence and reproduction](../../research/work-items/RE-004-i128-f64-rust-94/README.md)
include the complete body/FDE, relocation slot and observed callers, a
full-domain derivation, pre-Rust exact-rational expectations and real native
builds with deliberately incorrect variants. No captured code executes.
