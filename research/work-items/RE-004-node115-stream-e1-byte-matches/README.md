# RE-004: Node #115 First-Party Stream E1 (`assets`, `fees`, `orderbook`) Compiled-Byte Matches

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler**: `rustc 1.95.0 (59807616e 2026-04-14)` with `--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes --emit=obj`
- **Source**: independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust in `lib.rs` (static analysis and compilation only; no captured binary execution).

## Summary

**243 authenticated first-party `.text` FDE windows · 6,891 bytes compared · 5,826/6,891 (84.55%) raw-equal bytes · 243/243 (100.00%) relocation-qualified · 0 non-relocation byte mismatches · 0 overlap with `research/byte-windows.json`, `RE-007-node115-stream-e2-byte-matches`, or `RE-009-node115-storage-abci-byte-matches`.**

| Component | Windows | Bytes | Raw-equal bytes | Relocation-qualified |
| --- | ---: | ---: | ---: | ---: |
| `assets` | 77 | 2,741 | 2,340/2,741 (85.37%) | 77/77 |
| `fees` | 59 | 1,475 | 1,239/1,475 (84.00%) | 59/59 |
| `orderbook` | 107 | 2,675 | 2,247/2,675 (84.00%) | 107/107 |
| **Total** | **243** | **6,891** | **5,826/6,891 (84.55%)** | **243/243** |

## Matched Windows

### 1. `assets` — 8 Real `PerpMeta` / `SpotMeta` / `TokenSpec` Business-Logic FDEs (`1,016 B`, `888/1,016 = 87.40%` raw-equal)
- `0x3c4b1a0..0x3c4b274` (**212 B**, 196/212 raw, 4 rels): `SpotMeta::checked_sz_to_wei` (`l1/src/spot_meta.rs:119,1206`)
- `0x50bea90..0x50beb2f` (**159 B**, 131/159 raw, 7 rels): `PerpMeta::px_to_f64` (`l1/src/perp_meta.rs:163,287`)
- `0x3c4b280..0x3c4b30c` (**140 B**, 132/140 raw, 2 rels): `TokenSpec::wei_per_sz` (`l1/src/spot_meta.rs:1206`)
- `0x50beb30..0x50bebba` (**138 B**, 118/138 raw, 5 rels): `PerpMeta::sz_to_f64` (`l1/src/perp_meta.rs:163`)
- `0x3c47ae0..0x3c47b59` (**121 B**, 105/121 raw, 4 rels): `SpotMeta::spot_for_quote` (`l1/src/spot_meta.rs:119,590`)
- `0x3d19800..0x3d19868` (**104 B**, 88/104 raw, 4 rels): `PerpMeta::px_decimals` (`l1/src/perp_meta.rs:163,287`)
- `0x3d1a2c0..0x3d1a314` (**84 B**, 68/84 raw, 4 rels): `SpotMeta::quote_name_pair` (`l1/src/spot_meta.rs:119,590`)
- `0x3c47660..0x3c4769a` (**58 B**, 50/58 raw, 2 rels): `SpotMeta::first_spot_for_token` (`l1/src/spot_meta.rs:119`)

### 2. `assets` — 69 `Visitor::expecting` FDEs across 23 Core Types (`1,725 B`)
- `Side`, `PerpAssetInfo`, `PerpMeta`, `SpotInfo`, `SpotMeta`, `TokenInfo`, `TokenSpec`, `Aqav2TokenInfo`, `TokenInfos`, `Pdi`, `Px`, `Sz`, `Szi`, `Ntl`, `Ntli`, `Wei`, `SideMap`, `UsdcPx`, `UsdcNtl`, `UsdcNtli`, `UsdcBigSpotNtl`, `UsdcNtlScaleSerde`, `UsdcRoughNtli` (exact VAs in `records.json`).

### 3. `fees` — 59 `Visitor::expecting` FDEs across 20 Core Types (`1,475 B`)
- `FeeSchedule`, `NewFeeSchedule`, `FeeTiers`, `FeeTracker`, `FeeTrial`, `VipFees`, `MmFees`, `UserFeeState`, `ReferralState`, `ReferrerState`, `StakeDiscount`, `StakeDiscountTiers`, `CollectedBuilderFees`, `UnvalidatedHip3DeployerFee`, `AddCrossScaledVlm`, `ScaledAndRawVlm`, `DailyScaledVlms`, `FeeRateMapSerde`, `RawVlm`, `ScaledVlm` (exact VAs in `records.json`).

### 4. `orderbook` — 107 `Visitor::expecting` FDEs across 36 Core Types (`2,675 B`)
- `Tpsl`, `OrderDescription`, `UntriggeredOrder`, `Book`, `BookOrder`, `BookOrderKey`, `BookOrders`, `Books`, `Level`, `LevelSummary`, `Slab`, `OrderCore`, `OrderWireSerde`, `OrderBuilderInfo`, `OpenOrderTracker`, `Cancel`, `CancelByCloid`, `Cloid`, `CloidTracker`, `UserCloidTracker`, `ModifyWire`, `ScheduledCancel`, `Trigger`, `TriggerOrder`, `TriggerWireSerde`, `TrailingStopOrder`, `TwapId`, `TwapDetailsWire`, `TwapHeapKey`, `TwapSchedule`, `TwapState`, `TwapTracker`, `TwapTrigger`, `TwapTriggerWire`, `TwapWireSerde`, `WaitingTwap` (exact VAs in `records.json`).

## Reproducibility

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-004-node115-stream-e1-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_stream_e1_byte_matches_115
```

## Scope Boundary

- This packet proves 243 additional first-party `.text` FDE compiled-byte matches (`6,891 B`) for `assets`, `fees`, and `orderbook` ready for registration in `research/byte-windows.json`, and does not by itself claim full-component `identity` gates.
