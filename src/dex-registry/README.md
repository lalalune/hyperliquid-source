# `dex-registry` — Integrated Node #115 DEX Registry & HIP-3 Codecs

Target binary: Linux x86-64 `hl-node` #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Integrates the existing HIP-3 micro-crates (`node115-hip3-disabled-state-codec`,
`node115-hip3-disabled-record`) with independently authored Rust reconstructions
of the binary-verified #115 DEX registry routines:

- `dex-registry-main-hip3-state-codec-115` (`0x2bc2700`, `0x2b94d80` Main/Hip3 enum codec)
- `dex-registry-hip3-limits-schema-state-115` (`0x2bc1190`, `0x2bc17c0`, `0x2bc0900`)
- `dex-registry-hip3-subrecord-helpers-115` (`0x2ce96a0`, `0x2ce6f90`, `0x2cea920`, `0x226cf70`)
- `dex-registry-sub-deployers-115` (`0x22927f0`, `0x2bc7610`, `0x2bc6150` — all 23 deploy actions + `0x` lowercase hex address sets)
- `l1/src/dex_registry/perp_dex.rs:29,34` (`0x4201750`, `0x42017d0` — checked PDI indexing over `Vec<PerpDex>`, stride `0x200`)
- `l1/src/dex_registry/clearinghouses.rs:11,17` (`0x2753a70` — checked PDI indexing over `Vec<Clearinghouse>`, stride `0x510`)
- `l1/src/dex_registry/dex_registry.rs:37` (`0x2c774c0` — cross-DEX user-state scan)

## Scope and limitations

- Pure standard-library Rust (`#![forbid(unsafe_code)]`), no external crates.io dependencies.
- Reconstructs established static and byte-executed semantics only; does not claim
  full-node binary identity or component gate completion.

## Test

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 \
  CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --manifest-path src/dex-registry/Cargo.toml
```
