# RE-007-node115-stream-e2-debug-byte-matches

## Scope
Live-compiled, zero-overlap, 100.00% relocation-qualified non-visitor first-party `Debug::fmt` and `Display::fmt` compiled-byte FDE matches across **5 Stream E2 components (`risk`, `vaults`, `l1-shared`, `action-wire`, `exchange`)** against Linux x86-64 `hl-node` #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

Compiled live from pure-std `#![forbid(unsafe_code)]` Rust (`main.rs`, 0 external crates.io dependencies) using:
`rustc +1.95.0 --edition=2021 --crate-name stream_e2_dbg -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps`

## Verified Results (36 strictly disjoint non-visitor FDEs = 8,901 B; 7,749/8,901 = 87.06% raw-equal)
- **`risk` (8 FDEs / 2,050 B)**:
  - `MarginTableId::fmt` (`0x44eaf00`, 293 B)
  - `RawLeverage::fmt` (`0x44e87a0`, 293 B) & `<&RawLeverage as Debug>::fmt` (`0x4228bf0`, 296 B)
  - `<&AdlRequirement as Debug>::fmt` (`0x44db9d0`, 221 B — `user` `+0x10`, `position_index` `+0x00`)
  - `<&&Liquidatable as Debug>::fmt` (`0x42287a0`, 256 B — `user` `+0x18`, `position_index` `+0x00`, `margin_available` `+0x10`)
  - `PositionIndex::fmt` (`0x4305a20`, 214 B) & `<&PositionIndex as Debug>::fmt` (`0x3c4cda0`, 217 B — `Cross | Isolated { asset }`)
  - `CumFunding::fmt` (`0x44e85c0`, 260 B — `all_time`, `since_open`, `since_change`)
- **`vaults` (2 FDEs / 386 B)**:
  - `Ownership::fmt` (`0x44e5c60`, 221 B — `fraction`, `basis`)
  - `<&&vaults::UserState as Debug>::fmt` (`0x44dbab0`, 165 B — `ownership`, `net_ledger_change`, `vault_entry_time`, `last_deposit_time`)
- **`l1-shared` (12 FDEs / 3,422 B)**:
  - `<&Nonce as Debug>::fmt` (`0x2c7c910`, 296 B)
  - `Decibps::fmt` (`0x2e21fb0`, `0x5960b20`, 2 × 293 B) & `<&Decibps as Debug>::fmt` (`0x2c7c7e0`, `0x53d4ce0`, 2 × 296 B)
  - `PriorityRate::fmt` (`0x2453910`, 293 B) & `<&PriorityRate as Debug>::fmt` (`0x241ea90`, `0x50d8a20`, 2 × 296 B)
  - `PriorityRateLimit::fmt` (`0x51f5840`, 293 B)
  - `<&Float as Debug>::fmt` (`0x44db400`, 296 B)
  - `<&OrderBuilderInfo as Debug>::fmt` (`0x5940be0`, 253 B — `builder` `+0x20`, `fee_rate` `+0x18`, `sub_builders` `+0x00`)
  - `<&SubBuilder as Debug>::fmt` (`0x5941770`, 221 B — `builder` `+0x08`, `share` `+0x00`)
- **`action-wire` (11 FDEs / 2,459 B)**:
  - `<&TwapId as Debug>::fmt` (`0x5a2e210`, 296 B)
  - `<&Oid as Debug>::fmt` (`0x5941a80`, 296 B)
  - `<&TrailingStopOrder as Debug>::fmt` (`0x2d47e90`, `0x2d47f50`, `0x5a2c0b0`, `0x5a2ea20`, 4 × 165 B = 660 B — `activation_px`, `best_px`, `core`, `retracement`)
  - `<&TriggerOrder as Debug>::fmt` (`0x5a2c190`, `0x5a2ece0`, 2 × 224 B = 448 B — `core` `+0x00`, `trigger` `+0xb8`)
  - `<&Trigger as Debug>::fmt` (`0x5a2e0e0`, `0x5a2e630`, 2 × 253 B = 506 B — `is_market` `+0x08`, `trigger_px` `+0x00`, `tpsl` `+0x09`)
  - `Relationships::fmt` (`0x5aa8480`, 253 B — `children` `+0x20`, `parent` `+0x00`, `sibling` `+0x10`)
- **`exchange` (3 FDEs / 584 B)**:
  - `<&exchange::UserState as Debug>::fmt` (`0x5941020`, `0x5941850`, 2 × 253 B = 506 B — `book_order_keys`, `reduce_only_oids`, `untriggered_orders`)
  - `<ExchangeKind as Display>::fmt` (`0x1696db0`, 78 B — `Exchange`, `Rpc`, `EvmState` via `Formatter::pad`)

## Disjointness & Negative Controls
- Every window matches an exact FDE extent in `work/index/node-115-fde.tsv`, references its authentic RIP-relative `.rodata` type/variant string in node #115, has **0 non-relocation diffs**, and has **0 overlaps** internally, with `research/byte-windows.json`, and with all sibling `research/work-items/*/records.json` packets (Wave-4 consolidation-safe).
- `verify.py --self-test` verifies 4 negative controls (non-reloc byte flip, internal overlap, external overlap with `byte-windows.json`, bogus `.rodata` anchor).

## Verification
- `sha256sum -c MANIFEST.sha256`
- `PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-stream-e2-debug-byte-matches`
- `PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-stream-e2-debug-byte-matches/verify.py --self-test`
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e2_debug_byte_matches_115 -v`
