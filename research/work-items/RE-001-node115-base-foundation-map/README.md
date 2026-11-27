# RE-001: Node #115 `base` (`foundation`) Crate Map & Binary Anchors

- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `foundation` (`base/*`)
- **Method**: Static ELF parsing of `.rodata`, `.data.rel.ro`, `.rela.dyn`, `.eh_frame_hdr`/`.eh_frame` FDEs, and `.text` RIP-relative xrefs. No captured execution or emulation.

## Observations (ELF-verified in `records.json`)

- **33/33** observed `base/src/*.rs` diagnostic source paths are bound to **247** `.data.rel.ro` `core::panic::Location` structs and **839** distinct referencing `.text` FDEs (`l1_map/entry.rs`: 410 FDEs, `lock_id.rs`: 153, `lu.rs`: 82, `u.rs`: 60, `bucket_guard.rs`: 30, `file_mod_time_tracker.rs`: 27, `wallet.rs`: 23, `fu.rs`: 12, and all 25 remaining files).
- **12 exact `.rodata` anchors** verified by file offset and VA:
  - `base/src/cid.rs` (`0x154d390..0x154e96a`): `Usdc2Mainnet` (`0xaf88d065e77c8cC2239327C5EDb3A432268e5831`), `Bridge2Mainnet` (`0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7`), `Bridge2Testnet` (`0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89`), `Usdc2Testnet` (`0x1baAbB04529D43a73232B713C0FE471f7c7334d5`).
  - `base/src/api_url.rs` (`0x154afa0..0x154b3ac`): `https://api.hyperliquid.xyz/`, `https://api.hyperliquid-testnet.xyz/`, `http://localhost:3001/` (`WebSandbox`).
  - `base/src/build_mode.rs` (`0x1564870..0x1564b2b`): `"debug"`, `"release"`, `"run-client"`.
  - `base/src/c_guard.rs`: `"CGuard was set too many times"`.
  - `base/src/singleton_set.rs` (`0x1560ab0..0x1560e2f`): `"SingletonSet could not register "`.
  - `base/src/ema_tracker.rs` (`0x5a30130..0x5a305da`): `"assertion failed: self.denom > 0."`.
  - `base/src/chain_ext.rs` (`0x14cd400..0x14cdb33`): `"non-testing local chain"`.
- **`base/src/time.rs` FDE `0x15027d0..0x15028e1` (273 B)**:
  - Body SHA-256 recorded in `records.json`; embeds `1_000_000_000` (`0x3b9aca00`, nanoseconds/sec), `86_400` (`0x15180`, seconds/day), and `719_163` (`0xaf93b`, `1970-01-01` proleptic Gregorian day offset passed into `daycount-date`).

## Integrated Reconstruction (`src/node115-base`)

`src/node115-base` is an independently authored, `#![forbid(unsafe_code)]`, zero-external-dependency Rust crate that links all 39 Cargo-packaged `foundation` micro-crates and implements the `#115`-grounded `cid`, `api_url`, `build_mode`, `time`, and `guards` (`CGuard`, `SingletonSet`, `EmaTracker`) modules.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-base-foundation-map/verify.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_base_foundation_map_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/deps-forks cargo test --offline --locked --manifest-path src/node115-base/Cargo.toml
```

## Unknowns and Limitations

- Diagnostic paths only enumerate `base` files that emit surviving `Location` structs; panic-free or inlined modules inside `base` are not bounded by this table alone.
- Networked HTTP/Slack/shell side-effect wrappers (`http_client.rs`, `curl.rs`, `slack_alert.rs`, `shell.rs`) are intentionally excluded from offline execution and deferred until runtime wiring.
- All `foundation` acceptance gates remain `false` until full-component behavior and whole-crate identity are verified.
