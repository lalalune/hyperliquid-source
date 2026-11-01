# Visor child-argument values

A real dependency-free Rust component for one conditional native value relation. `collect_child_args` copies canonical UTF-8 arguments into owned Strings in order until the first None. Some(empty) remains a real empty argument; embedded NUL, whitespace and every admitted byte are preserved.

None maps only to a native pointer 0, length 0 descriptor. Invalid UTF-8 is a new safe refusal, and host allocation failure is a separate refusal. Neither reproduces the opaque native error helper. `native_descriptor_bytes` checks the explicit 24*N<=2^63-1 interval premise without constructing native pointers or huge allocations.

The evidence target is Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`. The full existing validator/adapter/collector proofs are credited in [the implementation packet](../../research/work-items/RE-013-visor-child-args-rust/IMPLEMENTATION.md). Native valid-memory, frame, allocator and byte-copy conditions remain premises; the correspondence ends before the caller's opaque cleanup. Native layout/capacity/error behavior, process argv, public CLI grammar, original compiler and machine-code identity are outside scope.

The pinned research build uses Rust 1.94.1 on aarch64-apple-darwin. There are no external crates, build scripts, root workspace or target-execution interfaces.

```sh
cargo test --locked --offline --manifest-path src/visor-child-args/Cargo.toml
cargo test --locked --offline --release --manifest-path src/visor-child-args/Cargo.toml
```

The packet's `rust-validation/verify.py` and `build.py` provide usable **post-source** static regeneration and real input-only corpus/build validation. The historical `verify_precode.py` intentionally requires source absence and is not the final-checkout command. Exact commands, freezes, raw results and limits live in IMPLEMENTATION.md; passing finite comparisons is not a component completion gate.
