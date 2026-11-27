# RE-006: Node #115 Stream E1 ThinLTO + Business-Logic Compiled-Byte Matches (`orderbook`, `assets`, `fees`)

## Target Binary
- Path: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Size: `105,896,032` bytes
- Compiler profile: `rustc +1.95.0 --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps` (`#![forbid(unsafe_code)]`, 0 external dependencies)

## Summary (Observed)
This evidence packet compiles [`main.rs`](./main.rs) live with `rustc +1.95.0` using ThinLTO (`-C lto=thin`) and verifies **78 strictly disjoint first-party `.text` FDEs (30,364 B total)** across Stream E1 (`orderbook`, `assets`, `fees`):

| Component | Windows | Total Bytes | Highlights |
| --- | ---: | ---: | --- |
| `orderbook` | 66 | 27,425 B | `OrderCore::fmt` (12×636 B = 7,632 B), `BookOrder::fmt` (4×693 B + 4×699 B = 5,568 B), `OrderDescription::fmt` (7×582 B = 4,074 B), `&Level::fmt` (4×452 B = 1,808 B), `Relationships::fmt` (6×253 B = 1,518 B), `&LevelSummary::fmt` (4×221 B = 884 B), `Half::fmt` (4×177 B = 708 B), `&Trigger::fmt` (2×253 B), `&UserState::fmt` (2×253 B), `&TriggerOrder::fmt` (2×224 B), `&&UserCloidTracker::fmt` (2×224 B), `&PriorityDequeEntry::fmt` (2×221 B), `&PriorityKey::fmt` (2×221 B), `&CloidTracker::fmt` (2×180 B), `Cloid`/`Oid`/`TwapId` `DebugTuple` (2,081 B) |
| `assets` | 10 | 2,465 B | `SpotMeta::sz_to_f64_zero_fast` (3×133 B = 399 B: `0x269d6a0`, `0x50bebc0`, `0x57cdae0`), `Perp::fmt` / `&Perp::fmt` (1,181 B), `Spot::fmt` / `&Spot::fmt` (589 B), `&Token::fmt` (296 B) |
| `fees` | 2 | 474 B | `&OrderBuilderInfo::fmt` (253 B), `&SubBuilder::fmt` (221 B) |
| **Total** | **78** | **30,364 B** | **78/78 (100.00%) relocation-qualified; 0 non-relocation byte diffs; 0 overlaps with dependency windows or sibling packets** |

## In-Memory Struct Layout Discoveries Confirmed by Byte Matching
Matching `<T as Debug>::fmt` under ThinLTO pins the exact field ordering, niche-driven layout, and byte offsets inside node #115's core orderbook & fee structs:
- `OrderCore` (`0xb8` B): `sz` (`+0x00`), `relationships` (`+0x10`), `description` (`+0x48`), `builder` (`+0x58`), `limit_px: Px(NonZeroU64)` (`+0x90`, niche-ordered ahead of `timestamp`), `timestamp` (`+0x98`), `reduce_only` (`+0xa0`), `cloid` (`+0xa1`), `side` (`+0xb2`).
- `BookOrder` (`0x110` B): `prev_key` (`+0x00`), `next_key` (`+0x10`), `core` (`+0x20`), `priority_rate` (`+0xd8`, niche-ordered ahead of `resting_sz`/`orig_sz`), `resting_sz` (`+0xe0`), `orig_sz` (`+0xe8`), `oid` (`+0xf0`), `user` (`+0xf8`), `is_position_tpsl` (`+0x10c`), `tif` (`+0x10d`).
- `Level` (`0x80` B): `first_key` (`+0x00`), `last_key` (`+0x10`), `zero_region_front` (`+0x20`), `priority_deque` (`+0x30`), `priority_key_to_order_key` (`+0x50`), `summary` (`+0x70`).
- `OrderDescription` (11 variants in exact discriminant order): `Limit`, `Market`, `TakeProfitMarket`, `TakeProfitLimit`, `StopMarket`, `StopLimit`, `CloseForVaultWithdrawal`, `SpotDustConversion`, `BoleLiquidation`, `TwapSlice(TwapId)`, `TrailingStopMarket`.

## Verification Commands
```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-006-node115-stream-e1-thinlto-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e1_thinlto_byte_matches_115 -v
(cd research/work-items/RE-006-node115-stream-e1-thinlto-byte-matches && sha256sum -c MANIFEST.sha256)
```

## Gate Honesty
This packet records compiled-byte matches for 78 specific first-party FDEs (30,364 B) and makes no `research/progress.json` gate claims.
