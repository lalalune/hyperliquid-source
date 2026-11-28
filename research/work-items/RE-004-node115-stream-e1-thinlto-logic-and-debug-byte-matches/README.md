# RE-004: Node #115 Stream E1 (`assets`, `orderbook`) ThinLTO Business-Logic & `OrderCore::fmt` Compiled-Byte Matches (13 FDEs / 4,246 B)

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: Stream E1 — `assets`, `orderbook` (`RE-004` / `RE-006`).
- **Compiler profile**: `rustc +1.95.0 --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin`, `#![forbid(unsafe_code)]`, pure `std`, `0` external dependencies.

## Verified Non-Visitor First-Party `.text` FDE Matches (13 FDEs / 4,246 B)

1. **`assets` — Pure Business Logic (`11` FDEs / `2,974 B`)**:
   - `SpotMeta::set_deployer_trading_fee_share` (`l1/src/spot_meta.rs:125`, `logic.rs` lib):
     - `0x2c58880..0x2c58947` (`199 B`, `0` non-reloc diffs, `chain` offset `0x0b9a`)
     - `0x55cec80..0x55ced47` (`199 B`, `0` non-reloc diffs, `chain` offset `0x0b9a`)
     - `0x55ced50..0x55cee17` (`199 B`, `0` non-reloc diffs, `chain` offset `0x170a`)
     - Enforces the exact `#115` `<= 100_000` (`0x186a0`) cap, legacy Mainnet (`token <= 195 && chain == 3`) one-time initialization and no-reset-to-zero rule, strictly decreasing update rule, `UserError` `0x00ee` / `Result::Ok(())` `0x01a2` discriminants, and `.rodata` error strings (`0x7bc1d5`, `0x7bc389`, `0x7bc3ac`).
   - `SpotMeta::px_from_wire` (`l1/src/spot_meta.rs:119,590,1055`, `main.rs` ThinLTO bin):
     - `0x29ae8c0..0x29ae9f8` (`312 B`, `0` non-reloc diffs)
     - `0x593d7e0..0x593d918` (`312 B`, `0` non-reloc diffs)
     - Enforces `8u8.checked_sub(quote.wei_decimals - base.sz_decimals)` -> `10u64.checked_pow`, single `div` remainder/non-zero check, returning `Result<u64, UserError>` (`0x0069` / `0x01a2`).
   - `SpotMeta::dual_px_to_f64` (`l1/src/spot_meta.rs:119,590,1055`, `main.rs` ThinLTO bin):
     - `0x22f5de0..0x22f5f48` (`360 B`, `0` non-reloc diffs)
     - `0x50e9d40..0x50e9ea8` (`360 B`, `0` non-reloc diffs)
   - `SpotMeta::px_to_f64` (`l1/src/spot_meta.rs:119,590,1055`, `main.rs` ThinLTO bin):
     - `0x50be9e0..0x50bea85` (`165 B`, `0` non-reloc diffs)
   - `PerpMeta::dual_px_to_f64` (`l1/src/perp_meta.rs:163,287`, `logic.rs` lib):
     - `0x22f5c80..0x22f5ddd` (`349 B`, `0` non-reloc diffs)
     - `0x50e9be0..0x50e9d3d` (`349 B`, `0` non-reloc diffs)
     - Exact `asset / 10_000 == pdi`, `asset % 10_000 < universe.len()`, `6usize - sz_decimals`, `POW10` division.
   - `qtys::scale_nonneg_i64` (`l1/src/qtys/mod.rs:847`, `logic.rs` lib):
     - `0x46a6aa0..0x46a6b4a` (`170 B`, `0` non-reloc diffs)
     - Exact `u64::try_from(x).unwrap()`, finite check, `[i64::MIN as f64, (i64::MAX as f64).next_down()]` clamp, and `.max(0)` saturation.
2. **`orderbook` — Remaining ThinLTO `DebugStruct::fmt` CGU Copies (`2` FDEs / `1,272 B`, `main.rs` ThinLTO bin)**:
   - `OrderCore::fmt`: `0x5aa99e0..0x5aa9c5c` (`636 B`), `0x5aa9c60..0x5aa9edc` (`636 B`)

All **13/13** FDEs are **100.00% relocation-qualified (`0` non-reloc diffs)**, strictly disjoint internally, strictly disjoint from `research/byte-windows.json` (Wave-4 consolidation-safe), and strictly disjoint from all sibling compiled-byte packets (enforced inside `verify.py` across both `start`/`end` and `start_va`/`end_va`/`va`+`size` schemas).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-004-node115-stream-e1-thinlto-logic-and-debug-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e1_thinlto_logic_debug_byte_matches_115 -v
(cd research/work-items/RE-004-node115-stream-e1-thinlto-logic-and-debug-byte-matches && sha256sum -c MANIFEST.sha256)
```
