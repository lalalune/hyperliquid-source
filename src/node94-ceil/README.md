# node94 binary64 ceiling

Independently authored `no_std`, allocation-free Rust for the scalar result of
node94 ELF VA `[0x565f670, 0x565f6e7)`. New code uses MIT. The captured binary
and its earlier disassembly retain their upstream rights.

`ceil_bits(u64) -> u64` admits every binary64 encoding. `ceil(f64) -> f64`
applies the same rule through Rust's bit-conversion methods. Both preserve
signed zero and return infinity/NaN encodings unchanged, including signaling
NaN bits. The implementation uses integer operations only.

This is a standalone value component with no external dependencies, build
hooks or Cargo workspace. The build is pinned to Rust 1.94.1; the exact rustc
flags, host target and two-build hashes are in the
[evidence packet](../../research/work-items/RE-004-ceil-rust-94/README.md).

From the repository root with Rust 1.94.1 selected:

```sh
rustup run 1.94.1 python3 -B research/work-items/RE-004-ceil-rust-94/verify_rust.py --out work/ceil-rust-check
```

The verifier requires a new output directory. It authenticates the predecessor
packet and target, builds this new Rust on the host, checks both public APIs
at optimization levels 0 and 3, and rejects four compiled semantic mutants.
The input-only driver receives no expected outputs. Captured machine code is
never executed or emulated by this verifier.

The original symbol, crate/library provenance, calling ABI, upper XMM lanes,
caller domain, and Linux target-byte equivalence remain unqualified. These
functions are not asserted to be drop-in original ABI replacements.
