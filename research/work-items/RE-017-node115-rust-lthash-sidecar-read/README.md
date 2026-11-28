# Read native decimal-array LtHash sidecars in Rust checkpoint restore

The Rust ABCI bundle reader accepted its local hexadecimal lane encoding only. A native-shaped JSON sidecar instead stores each lane as 2,048 unsigned byte values. The existing bundle entry point now restores either representation into its three `LtHash` records. It preserves the local bundle writer and metadata format.

The [EVM checkpoint hash packet](../RE-011-evm-db-checkpoint-hashes-115/README.md) binds the three named lane writers in `0x38c2230` to `0x36c5cf0`. Its selected hash-field helper passes length `0x800` at `0x4654603` to `0x4670ae0`, where the decimal branch uses a zero-extended byte and the array closes with `]`. [PR #7337](https://github.com/lalalune/hyperliquid-source/pull/7337) projected that JSON through a Python adapter. [PR #7513](https://github.com/lalalune/hyperliquid-source/pull/7513) adds a native-format writer. This ingress adds the missing Rust reader path at the bundle boundary.

The offline regression reloads a real temporary bundle in its legacy format, then replaces only its sidecar with independently generated native-style arrays containing every u8 value and distinct counters. It checks all three exact records, and rejects arrays with the wrong width or decimal values outside the selected byte form. The test exercises the writer-emitted shape. Full native field parsing, real checkpoint provenance and complete restored root alignment remain outside scope.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-rust-lthash-sidecar-read/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test native_lthash_sidecar_read
```

The [offline log](offline-log.txt) records the red baseline, static checks and passing Rust suites. The verifier reads the captured executable as ELF data.
