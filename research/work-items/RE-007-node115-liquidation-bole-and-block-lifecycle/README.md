# RE-007 / RE-010: node #115 Cross Backstop Liquidation Allocator (`0x44dcf80`), Borrow-Lend Liquidation Order (`0x2c80670`), and `begin_block` / `end_block` Lifecycle

- Component IDs: `risk`, `exchange` (`RE-007` / `RE-010`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: **observation** for all 5 FDE extents (`0x44dcf80`, `0x3d987f0`, `0x2c80670`, `0x2bdf8f0`, `0x2c71250`), all 7 `begin_block` phase string VAs, LEA instruction sites, and `.rodata` bucket-guard pairs (`0x453890`/`0x453530`/`0x453520`), the `0xbb * 20` bole liquidator address (`0x60e1c7` & `0x4518f0` + `0x2c80913`), `"Liquidator must use cross margin for asset "` (`0x444f1c`), the `0x2c719c3 -> 0x2bda7c0` `end_block` action-router call, 5 instruction anchors, and 5 relocated panic `Location` records; **inference** for reconstructed Rust APIs in `src/clearinghouse/src/liquidation.rs` and `src/exchange/src/bole_liquidation.rs`.
- Remaining unknowns: full multi-user ADL ranking loop inside `0x446c200` (24,065 B) and full inner matching-engine fill settlement callee `0x449bd50` (`GOT 0x64e7f30`).

## Evidence (node #115 static observations)

### 1. Core Financial Lifecycle FDEs

| Function VA (size) | Observed #115 behavior & anchors |
| --- | --- |
| `0x44dcf80..0x44dd1a4` (548 B) | `Clearinghouse::backstop_liquidate_position_allocation` (`l1/src/clearinghouse/clearinghouse.rs:179:98`, `0x648bb28`): HIP-3 `asset % 10_000` (`0x44dcf91`), `mark_px >= 0` & `checked_mul(szi)`, `total_abs_ntl == 0 -> None`, pro-rata `(|ntli| / total_abs_ntl) * account_value`, finite-clamp `i64`, `liquidation_pnl = alloc - ntli`, decrements `remaining_account_value`. |
| `0x3d987f0..0x3d98b32` (834 B) | `l1/src/clearinghouse/clearinghouse.rs:544:18` (`"Missing price, keeping old .. price"` at `0x43af28`). |
| `0x2c80670..0x2c80a3d` (973 B) | `Exchange::bole_liquidation_spot_order` (`l1/src/exchange/impl_bole.rs:384:35`, `0x644d9c0`): rejects `token == 0`, selects first `(token, quote=0)` spot market, saturating-increments `oid`, rounds `spot_px * mult` via `0x63efe40` (`f64::round`) with `0 -> 1` floor (`0x2c808ab`), and builds forced IOC (`tif = 1`, `0x2c809a4`) cross against `0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` (`0x4518f0` + `0x2c80913`). |
| `0x2bdf8f0..0x2beafa1` (46,769 B) | `Exchange::begin_block` (`begin_block.rs:266:51`, `0x644d738`): runs 7 named periodic phases in exact VA order below. |
| `0x2c71250..0x2c71ea5` (3,157 B) | `Exchange::end_block` (`end_block.rs:194:32`, `0x644d9a8`): directly invokes the 92-arm central action router `0x2bda7c0` at `0x2c719c3`. |

### 2. `Exchange::begin_block` 7-Phase Periodic Schedule (`0x2bdf8f0`)

| Order | Phase string (`VA`) | LEA site in `0x2bdf8f0` | Bucket guard (`VA`) |
| ---: | --- | --- | --- |
| 1 | `distribute_funding` (`0x60e19e`) | `0x2bdfb11` | `(0.35, 0.05)` (`0x453890`) |
| 2 | `update_funding_rates` (`0x60e1db`) | `0x2be0732` | `(0.01, 0.05)` (`0x453530`) |
| 3 | `cancel_aggressive_orders_at_oi_cap` (`0x60e23a`) | `0x2be11a0` | `(0.01, 0.05)` (`0x453530`) |
| 4 | `prune_book_empty_user_states` (`0x60e21e`) | `0x2be191a` | `(0.05, 0.05)` (`0x453520`) |
| 5 | `refresh_main_perp_dex_stale_oracle` (`0x60e25c`) | `0x2be66b6` | `(0.01, 0.05)` (`0x453530`) |
| 6 | `refresh_hip3_stale_mark_pxs` (`0x60e203`) | `0x2be6cb5` | `(0.01, 0.05)` (`0x453530`) |
| 7 | `apply_bole_liquidations` (`0x60e1b0`) | `0x2be7ab5` | `(0.01, 0.05)` (`0x453530`) |

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_liquidation_bole_and_block_lifecycle_115
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-liquidation-bole-and-block-lifecycle
(cd research/work-items/RE-007-node115-liquidation-bole-and-block-lifecycle && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/clearinghouse/Cargo.toml
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/exchange/Cargo.toml
```
