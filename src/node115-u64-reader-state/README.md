# Node115 u64 reader state

An independently authored, allocation-free `no_std` logical implementation of
one frozen RE-005 relation. This is not the original Rust ABI or a full codec.
See [the evidence packet](../../research/work-items/RE-005-node115-u64-reader-state/README.md)
and its pre-implementation CONTRACT.md for exact target, domain and limitations.
No external crates, build scripts or captured-code execution are used.

`Reader::new(input, None, count)` is canonical unlimited mode0; `Some(limit)`
is canonical limited mode1. Reads mutate remaining input and count on errors:
over-limit charges remain stored; overflow leaves count unchanged; invalid
markers consume one byte only on the short-input route. `read_four` reserves
32 before reading and retains that full charge after partial errors. Errors
expose only observed active fields, preserving unknown original enum labels.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```

Windows gnullvm builds require official rust-mingw and explicit rust-lld; the
packet documents the tested version/flags. Linux library build was inspected,
not executed or linked into a node. The probe is an offline test adapter, not
a network protocol or production node entrypoint. No progress gate is changed.
