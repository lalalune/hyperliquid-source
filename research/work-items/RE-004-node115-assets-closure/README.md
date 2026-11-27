# RE-004: Node #115 Complete `assets` (`l1/src/asset/*`, `l1/src/qtys/*`, `perp_meta.rs`, `spot_meta.rs`, `wire_qty.rs`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `assets` (`l1/asset/*`, `l1/qtys/*`, `l1/perp_meta.rs`, `l1/spot_meta.rs`, `l1/wire_qty.rs` — Stream E1 / `RE-004`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `assets` source file (**8/8**: `l1/src/asset/pdi.rs`, `l1/src/perp_meta.rs`, `l1/src/spot_meta.rs`, `l1/src/wire_qty.rs`, `l1/src/qtys/impl_ntl.rs`, `l1/src/qtys/impl_sz.rs`, `l1/src/qtys/impl_wei.rs`, `l1/src/qtys/mod.rs`), **every** `.data.rel.ro` `Location` struct (**144/144**, `0` unreferenced), **every** `.text` FDE referencing those `Location` structs (**783/783 unique FDEs = 2,020,566 bytes**), and **12** core business-logic FDEs (`2,999 B`) verified against raw ELF bytes and `work/index/node-115-fde.tsv`.

## Complete Source-File Closure (8/8 Observed Files)

1. **`l1/src/asset/pdi.rs` (10 Locations, 45 FDEs / 303,181 B)**:
   - `:32:14` `Pdi` index stride (`PDI_STRIDE = 10_000`) and asset-index encoding (`PerpAsset`, `SpotAsset`, `Token`, `Side`).
   - Mapped to `src/node115-assets/src/pdi.rs`.
2. **`l1/src/perp_meta.rs` (3 Locations, 115 FDEs / 264,301 B)**:
   - `:163:38` (113 FDEs: asset metadata bounds lookup), `:247:72` (`0x3c43150`, 420 B: margin-table lookup with built-in 1-tier table threshold `id < 50` at `0x3c4315d: cmp edx, 0x32` vs custom BTreeMap lookup), `:287:28` (59 FDEs: `PerpMeta` asset helper).
   - Mapped to `src/node115-assets/src/meta.rs`.
3. **`l1/src/spot_meta.rs` (22 Locations, 350 FDEs / 920,238 B)**:
   - `:119:33` (260 FDEs: token info lookup), `:125:37` (25 FDEs: token info mut/validation), `:590:25` (spot info lookup across 17 CGU Locations), `:1055:9` (52 FDEs: decimal scale subtraction overflow check), `:1074:69` (`0x3c49360`, 211 B: `usdc_wei_per_base_sz` powers-of-10 ladder), `:1206:57` (12 FDEs: spot decimal/pair checks), plus `has_usdc_spot` (`0x3c49df0`, 122 B), `px_to_f64` (`0x50be9e0`, 165 B), `sz_to_f64_zero_fast` (`0x269d6a0`/`0x50bebc0`/`0x57cdae0`, `3 × 133 B`), and `set_deployer_trading_fee_share` (`0x2c58880`/`0x55cec80`/`0x55ced50`, `3 × 199 B`).
   - Mapped to `src/node115-assets/src/meta.rs`.
4. **`l1/src/wire_qty.rs` (1 Location, 1 FDE / 915 B)**:
   - `:29:48` (`0x41c57f0`, 915 B: 96-bit decimal normalization stripping trailing factors of 10 from scale 8).
   - Mapped to `src/node115-assets/src/wire_qty.rs`.
5. **`l1/src/qtys/impl_ntl.rs` (28 Locations, 153 FDEs / 733,992 B)**, **`l1/src/qtys/impl_sz.rs` (13 Locations, 39 FDEs / 183,590 B)**, **`l1/src/qtys/impl_wei.rs` (1 Location, 83 FDEs / 544,697 B)**, and **`l1/src/qtys/mod.rs` (66 Locations, 281 FDEs / 1,108,696 B)**:
   - Fixed-point `Px`, `Sz`, `Szi`, `Ntl`, `Ntli`, `Wei`, `Usdc`, `UsdcSigned` checked/saturating arithmetic, overflow sinks, `POW10_F64` (`.rodata 0x91b7c0` / `0x60d448`), and `scale_nonneg_i64_by_f64_clamped` (`0x46a6aa0`, 170 B).
   - Mapped to `src/node115-assets/src/qtys.rs`.

## Complete `assets` Acceptance Inventory

- **Mapped**: 8/8 `assets` source files, 144/144 `Location` structs (`0` unreferenced), 783/783 Location-referencing FDEs (`2,020,566 B`), and 12 core business FDEs (`2,999 B`) verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/node115-assets` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/hl-node`, `src/node115-fees`, `src/node115-orderbook`, `src/clearinghouse`, `src/exchange`) combines all verified Cargo-packaged `assets` micro-crates with binary-grounded implementations of `Pdi`/`PerpAsset`/`SpotAsset`/`Token`/`Side`, `PerpMeta` (including built-in `< 50` margin-table rule), `SpotMeta` (decimal conversions, `usdc_wei_per_base_sz`, `has_usdc_spot`, `update_deployer_trading_fee_share`), `WireQty`/`Decimal96` normalization, and all `Px`/`Sz`/`Szi`/`Ntl`/`Ntli`/`Wei`/`Usdc` fixed-point operations.
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proof currently covers **10** non-visitor `assets` ThinLTO FDEs (`2,465 B`: `SpotMeta::sz_to_f64_zero_fast` `3 × 133 B` + `Perp`/`Spot`/`Token` `DebugTuple` `7w / 2,066 B`) in `RE-006-node115-stream-e1-thinlto-byte-matches` plus leaf `assets` helpers in `RE-004-node115-stream-e1-byte-matches`.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-004-node115-assets-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_assets_closure_115 -v
(cd research/work-items/RE-004-node115-assets-closure && sha256sum -c MANIFEST.sha256)
```
