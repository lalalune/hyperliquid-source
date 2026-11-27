# `info-api` (node #115)

Clean-room MIT Rust integration crate for Hyperliquid node #115's `info_server` (`info-api`) component.

## Target

- Artifact: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Binary evidence packet: `research/work-items/RE-015-node115-info-api-crate/`

## Integrated Scope

- **All 7 observed `info_server/src/*.rs` source paths** (`abci_state_info_handler.rs`, `f_types/position.rs`, `handle_request.rs`, `handler.rs`, `router.rs`, `save_l4_snapshots.rs`, `user_ip.rs`) and 43 `.data.rel.ro` panic `Location` records.
- **Complete 55-variant `InfoRequest` schema** (`0x643a9e0` `.data.rel.ro` variant table, `0x2744200` deserializer, `0x273bf30` serializer with jump table `0x5f45d0`), plus the 2-variant `FileSnapshotRequest` (`referrerStates`, `l4Snapshots` at `0x643ad50`).
- **Strict JSON request `"type"` extraction & error positioning** wired to `node115-json-string-scanner` and `node115-json-error-position`.
- **HTTP handler, timing, snapshot-guard, and future-state invariants** from `0x2e3ed10`, `0x29698d0`, `0x2979780`, `0x2a52620`, and `0x2a3ceb0`.
- **Position integer prefix & liquidation candidate scan** (`f_types/position.rs`) integrating `node115-position-integer` semantics with `node115-risk-candidate-scan`.
- **Replica JSON response emission & L4 snapshot options** wrapping `node115-replica-response-json` and `save_l4_snapshots.rs`.

## Verification

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/info-api/Cargo.toml
CARGO_BUILD_JOBS=4 cargo clippy --offline --locked --manifest-path src/info-api/Cargo.toml --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_info_api_crate_115 -v
```
