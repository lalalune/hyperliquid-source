# RE-015: Node #115 Stream F Logic Wave 2 Compiled-Byte FDE Matches (`70` FDEs / `29,815 B`)

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Compiler**: `rustc 1.95.0 (59807616e 2026-04-14)` (`x86_64-unknown-linux-gnu`), strictly `#![forbid(unsafe_code)]`, zero relaxations (`relaxed_sites = 0`), zero non-relocation byte diffs across all 70 FDEs.
- **Consolidation prefix**: `node115-stream-f-w2-` (strictly disjoint from live `research/byte-windows.json` and all sibling compiled-byte packets across both `start`/`end` and `start_va`/`end_va`).
- **Attribution**: 100% first-party Hyperliquid defining crates (`info_server`, `l1`), zero `core::`/`alloc::`/`std::`/`drop_in_place`/third-party attribution.

## Summary

| Component | FDEs | Total Bytes | Raw-Equal Bytes | Raw-Equal % | Defining Crate & Source Anchor |
|---|---:|---:|---:|---:|---|
| `info-api` (inner `async fn` poll) | 16 | 3,381 | 3,009 | 89.00% | `info_server/src/abci_state_info_handler.rs:81-82` (`0x6442de0`, `0x6442df8`) |
| `info-api` (outer `#[async_trait]` poll) | 52 | 26,358 | 23,318 | 88.47% | `info_server/src/abci_state_info_handler.rs:127:12` (`0x64434d0`) |
| `bridge` (`<BridgeRole as Display>::fmt`) | 1 | 50 | 34 | 68.00% | `l1` bridge role formatter (`.rodata` `0x7d3e55` `"Locker"`, `0x7d3e5b` `"Finalizer"`) |
| `evm` (`evm_state` `unreachable!()` stub) | 1 | 26 | 14 | 53.85% | `l1/src/evm/evm_state.rs:183:9` (`0x648be28`, `.rodata` `0x7d247d`) |
| **Total** | **70** | **29,815** | **26,375** | **88.46%** | **4/4 `.data.rel.ro` `Location` + 3/3 `.rodata` anchors verified** |

Combined with `RE-015-node115-stream-f-async-and-rpc-logic-byte-matches` (`37` inner `info-api` FDEs / `6,996 B`), the `16` inner `info-api` FDEs here complete **53/53 (100%)** of the `abci_state_info_handler.rs:81-82` inner `async fn` `Future::poll` cluster, while the `52` outer `info-api` FDEs cover **52/54 (`26,358 / 27,180 B = 96.98%`)** of the `abci_state_info_handler.rs:127:12` `#[async_trait]` `Box::pin(...).await` wrapper cluster.

## Build Profiles

1. **`small.rs` (`18` FDEs / `3,457 B`, zero external crates)**:
   - `rustc +1.95.0 --edition=2021 --crate-type=bin --crate-name=stream_f_w2_small -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C codegen-units=1 --emit=obj`
   - Covers `<BridgeRole as Display>::fmt` (`0x457cf20`, `50 B`), `l1/src/evm/evm_state.rs:183:9` (`0x4493250`, `26 B`), and all `16` remaining inner `abci_state_info_handler.rs:81-82` `Future::poll` FDEs (`3,381 B`).
2. **`harness/` (`52` FDEs / `26,358 B`, locked 2-crate ThinLTO + `tikv-jemallocator = "=0.6.0"` workspace)**:
   - `cargo +1.95.0 rustc -p mybin --bin mybin --release --offline --locked -- -C save-temps` (`opt-level = 3`, `lto = "thin"`, `overflow-checks = true`, `#[global_allocator] tikv_jemallocator::Jemalloc`).
   - Zero proc-macro dependencies (`licenses.json`: all 6 external crates in `harness/Cargo.lock` are `MIT OR Apache-2.0`).
   - Two-crate ThinLTO (`mylib` library + `mybin` binary with `Jemalloc`) reproduces LLVM's inlining of `<Box<dyn Future> as Drop>::drop` (`tzcntq`/`cmova`/`_rjem_sdallocx`) in both the normal drop path and cold unwind pad, plus rustc's exact coroutine drop flags (`0x41`/`0x59`/`0x49`/`0x69`) for `String`/`Drop`-bearing arguments and stack-slot coloring with `Poll<R>`.

## Verification

```sh
# Fast verification against bodies.bin + hl-node + 4 negative controls:
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-stream-f-logic-wave2-byte-matches/verify.py --self-test

# Full offline live rebuild (compiles small.rs + harness/ offline & checks byte-for-byte identity):
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=work/target/stream-f-w2 \
  python3 research/work-items/RE-015-node115-stream-f-logic-wave2-byte-matches/verify.py --rebuild --self-test

# Manifest & targeted unittest:
(cd research/work-items/RE-015-node115-stream-f-logic-wave2-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_f_logic_wave2_byte_matches_115 -v
```
