# Packed-date difference, node115

Independent, dependency-free Rust value API for the complete normal-return
integer relation at linked VA 0x162a290..0x162a42b of authenticated node115.
This is a leaf reconstruction, not a recovered Chrono crate or native ABI.

Three u32 words project the packed date, seconds and nanoseconds. The result
contains i64 seconds and normalized u32 nanoseconds. None identifies the
observed zero-day-of-cycle boundary before the native panic call; it is not
the captured error type or panic behavior. Raw words outside valid timestamp
domains are deliberately not validated here.

The derivation, original evidence, reproducible vector generator, compiled
corruption controls and limitations are in
[RE-014-packed-date-difference-115](../../research/work-items/RE-014-packed-date-difference-115/README.md).

Build this actual component graph offline; no root node workspace is implied:

```sh
cargo test --locked --offline --manifest-path src/node115-packed-date-difference/Cargo.toml
cargo fmt --manifest-path src/node115-packed-date-difference/Cargo.toml -- --check
cargo clippy --locked --offline --manifest-path src/node115-packed-date-difference/Cargo.toml --all-targets -- -D warnings
```

Only authored probes are executed. No captured node/visor, clocks, network,
chain, private fixture, external provider or original panic helper is run.
