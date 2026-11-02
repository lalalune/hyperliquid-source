# Node #94 HyperEVM persistent state

This standalone crate is an independently authored offline implementation of the bounded
HyperEVM persistent account-state behavior established for Linux x86-64 `hl-node` #94,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It is intentionally not added to a root Cargo workspace because no recovered root workspace
contract exists.

## Proven original behavior

- Table 24 account keys are `Ea || address[20]` (22 bytes).
- Table 25 code keys are `Ec || code_hash[32]` (34 bytes).
- Table 26 storage keys are `Es || address[20] || slot[32 big-endian]` (54 bytes).
- Account values are named MessagePack maps. Fields are written as `b`, `n`, `c`; zero balance,
  zero nonce, and `keccak256("")` code hash are omitted. The 32-byte fields use MessagePack bin.
- Storage values are exactly 32 big-endian bytes.
- Stored code is a one-entry variant map. `LegacyRaw`, `LegacyAnalyzed`, and `Eip7702` writer
  forms are implemented. The `LegacyAnalyzed` jump-table data is an integer array in Lsb0 order,
  with unused high tail bits masked.
- Replacement removes an existing entry contribution before adding the replacement. Lattice
  words are 1,024 big-endian u16 values with wrapping arithmetic. The record and byte counters
  use saturating u64 arithmetic. BLAKE3 produces the 2,048-byte XOF contribution.

The corresponding native address map is:

| Role | ELF virtual address |
| --- | --- |
| code replacement | `0x326a6f0..0x326aa38` |
| dispatcher | `0x326aa40..0x326abc1` |
| account replacement | `0x326abd0..0x326aebc` |
| common accumulator addition | `0x37ebb90..0x37ebda1` |

## Implementation policy

The account reader accepts only the canonical writer form: original field order, omitted
defaults, and no trailing data. The retained account packet did not establish that the native
reader rejects every alternate MessagePack representation, so those rejections are crate policy.

The supported code reader accepts `LegacyRaw` and the exact writer-shaped `LegacyAnalyzed` map.
It accepts the outer fixmap/map16/map32 marker families observed in the target, but requires the
established field order. A nonzero jump-table head is rejected because its writer-domain selector
and reader checks are not completely recovered.

`OfflineState::prepare_replacement` reads the old value and computes old-before-new accounting,
but does not write the database. `apply_database_update` is separate so callers must select their
own commit/rollback policy. The deterministic `MemoryStore` is compiled only for tests or the
`test-fixtures` feature and is not presented as RocksDB.

## Unresolved contract

- The complete key/value entry serialization fed to BLAKE3 is not recovered. Callers must provide
  it through `EntryMaterializer`, which returns explicitly named `VerifiedEntryBytes`.
- Native RocksDB batch atomicity, writer errors, caller rollback, and deletion commit behavior are
  unresolved.
- The Eof nested list element encodings are incomplete, so Eof encoding fails explicitly.
- Eof and Eip7702 reader behavior, the LegacyAnalyzed native map-loop acceptance order, and some
  jump-table width/index/capacity checks remain unresolved.
- This crate does not implement snapshot files, height-key table codes, `/lt_hashes.json`, a state
  root, live chain access, or a network node.

## Build and test

Use the repository-pinned Rust 1.94.1 toolchain and the crate's own lockfile:

```sh
CARGO_BUILD_JOBS=2 cargo build --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 cargo build --release --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --release --locked --manifest-path src/node94-evm-state/Cargo.toml
CARGO_BUILD_JOBS=2 cargo clippy --locked --manifest-path src/node94-evm-state/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-evm-state/Cargo.toml -- --check
```

The evidence packet is at
[`research/work-items/RE-009-node94-evm-state-rust`](../../research/work-items/RE-009-node94-evm-state-rust/README.md).

