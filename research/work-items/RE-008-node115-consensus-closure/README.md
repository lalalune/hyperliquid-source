# RE-008: Node #115 Complete `consensus` (`node/src/consensus/*.rs`) Full-Scope 17-File / 115-Location Closure

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `consensus` (`node/consensus/*` in `research/components.json` — Stream D / `RE-008`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `node/src/consensus/*.rs` file (**17/17**), **every** `.data.rel.ro` `core::panic::Location` struct (**115/115**), **every** `.text` FDE referencing those `Location` structs (**54/54 unique FDEs = 213,310 B**), and **all 27 reconstructed consensus business-logic FDEs** across `src/node115-consensus` (now hardened with `#![forbid(unsafe_code)]`, `src/heartbeat.rs` closing `heartbeat_tracker.rs` `0x5a71e20`/`0x5a71ee0`, and end-to-end `tests/integration.rs`) plus all 18 sibling registered consensus implementation paths.

## Final `heartbeat_tracker.rs` Routines Closed Here

1. **`heartbeat_record_bucket` (`0x5a71e20..0x5a71ed9`, 185 B)**:
   - Evaluates the periodic bucket guard at `[tracker+0xb0]` (`call 0x57d37c0`), reads current wall-clock time (`call *0x64e0990`), and records per-validator heartbeat observations (`call 0x4d55380`).
2. **`heartbeat_latency_ema_180s` (`0x5a71ee0..0x5a722ec`, 1,036 B)**:
   - Reads current wall-clock time (`call *0x64e0990`), subtracts `0xb4` (**180 seconds** = 3 minutes) at `0x5a71f10` (`mov $0xb4, %edx; call *0x64e0f78`), and writes/tracks the `"validator_latency_ema"` (`.rodata 0x93b1d7`, len `0x15` = 21 B, loaded at `0x5a7203c..0x5a72050`) snapshot under `/file_mod_time_tracker/` (`.json`).

## Complete 17-File `consensus` Inventory & Implementation Mapping

All 17/17 `node/src/consensus/*.rs` files in `hl-node-115.inventory.json` (`config.rs`, `execution_state.rs`, `heartbeat_tracker.rs`, `latency_samplers.rs`, `liner.rs`, `mempool.rs`, `network.rs`, `node_ips.rs`, `rpc.rs`, `server.rs`, `signature_tracker.rs`, `signed.rs`, `state.rs`, `timer.rs`, `types.rs`, `validator_set.rs`, `validator_stakes.rs`) are verified directly against raw `.rela.dyn` + `.data.rel.ro` + `.text` + `work/index/node-115-fde.tsv` and mapped in `records.json` to `src/node115-consensus/src/{admission,block_rules,commit,heartbeat,proposer,round_progression,tc_verify,timeout_flow,voting,wire_codec}.rs` and the sibling registered consensus crates.

## Complete `consensus` Acceptance Inventory

- **Mapped**: 17/17 `node/src/consensus/*.rs` files, 115/115 `Location` structs, 54/54 Location-referencing FDEs (`213,310 B`) + 27 reconstructed business-logic FDEs verified against `work/index/node-115-fde.tsv`, `hl-node-115.inventory.json`, and raw ELF bytes.
- **Built & Behavior**: All 19 registered `implementation_paths` in `research/components.json` exist on disk; all 14 Cargo crates build offline and pass all tests; `src/node115-consensus` (`#![forbid(unsafe_code)]`, 0 external deps, linked into `src/hl-node`) passes all unit + integration tests in debug and `--release` and `clippy --all-targets -- -D warnings` with 0 warnings.
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`. Disjoint live-compiled `rustc 1.95.0` FDE matches currently cover **59 FDEs / 9,159 B** across `RE-008-node115-consensus-staking-byte-matches` (`31w / 775 B`) and `RE-008-node115-consensus-staking-debug-byte-matches` (`28w / 8,384 B`).

## Unknowns / Limits

- Cryptographic signature verification, TCP/TLS sockets, and async wall-clock timers remain abstracted behind trait/value boundaries in `src/node115-consensus`.
- Compiled-byte identity covers 59 FDEs (`9,159 B`) and does not close the full-component `identity` gate.

## Verification

```bash
cd research/work-items/RE-008-node115-consensus-closure && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-consensus-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_consensus_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/node115-consensus/Cargo.toml
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-consensus/Cargo.toml
CARGO_BUILD_JOBS=4 cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-consensus/Cargo.toml --all-targets -- -D warnings
```
