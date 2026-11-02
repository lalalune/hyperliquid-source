# node94 shifted-threshold scalar

Safe, dependency-free `no_std` value reconstruction of node #94 ELF VA
`0x565ede0..0x565ee3d`:

```rust
use node94_shifted_divisor_scalar::shifted_divisor_scalar;

assert_eq!(shifted_divisor_scalar(0, 1), u64::MAX);
assert_eq!(shifted_divisor_scalar(0, 2), (1u64 << 63) - 1);
assert_eq!(shifted_divisor_scalar(4, 3u128 << 64), 1);
```

Both u128 arguments accept their entire range. The native body loads a
little-endian 128-bit input through RDI and receives the threshold low/high
halves in RSI/RDX. This API replaces those arguments with numeric snapshots;
it does not reproduce the native pointer ABI, faults or register clobbers.

The result is the largest u64 `q` whose weighted cost fits the numerator:
`cost(q) = sum(bit(q,64-k) * (threshold >> k), k=1..64)`. For zero threshold
the result is all ones. When the threshold low half is zero and its high half is nonzero, this
equals ordinary saturating division by the high half.
No general division identity or source-library identity is claimed.

```sh
cargo +1.94.1 build --offline --locked --manifest-path src/node94-shifted-divisor-scalar/Cargo.toml
python3 research/work-items/RE-001-shifted-divisor-scalar-rust-94/verify.py --out work/shifted-scalar-review
```

The verifier uses installed GNU/LLVM decoders and a rustup Rust 1.94.1 shim;
override its macOS defaults with `GNU_OBJDUMP`, `LLVM_OBJDUMP`, and `--rustc`.
Its output directory must be fresh and under the repository. The separate
`std` client reads inputs only from stdin. The [evidence packet](../../research/work-items/RE-001-shifted-divisor-scalar-rust-94/README.md)
contains the complete derivation, frozen independent cost oracle and limits.
