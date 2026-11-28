# RE-007: Node #115 `vaults`/`risk` Pure Business-Logic Compiled-Byte FDE Matches (`10 FDEs / 1,823 B`)

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: `vaults` (`l1/src/sub_account.rs`) and `risk` (`l1/src/spot_clearinghouse/spot_clearinghouse.rs`, `l1/src/clearinghouse/clearinghouse.rs`) (Stream E2-A / `RE-007`).
- **Compiler & Flags**: `rustc 1.95.0 (59807616e 2026-04-14)` (`stubs.rs` compiled as `--crate-type=rlib -C opt-level=3 -C overflow-checks=yes -C embed-bitcode=no`; `main.rs` compiled as `--edition=2021 --crate-type=bin -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C codegen-units=1 --extern stubs=... --emit=obj`).
- **Disjointness & Safety**: `#![forbid(unsafe_code)]` on both `stubs.rs` and `main.rs`, 0 external crates.io dependencies, 0 `core::`/`alloc::`/`std::` attribution, 0 serde visitors, 0 internal overlaps, 0 overlaps with `research/byte-windows.json` or any sibling compiled-byte/census packet (checked across both `start`/`end` and `start_va`/`end_va`).

## Matched Pure First-Party Business-Logic FDEs (`10` FDEs, `1,823 B`, `1,650/1,823 = 90.51%` raw-equal)

### `vaults` (`2` FDEs, `347 B`, `325/347 = 93.66%` raw-equal)
1. **`SubAccountTracker::master_lookup`** (`l1/src/sub_account.rs`): `0x366af60..0x366b035` (`213 B`, `198/213` raw-equal, 4 reloc slots).
2. **`SubAccountTracker::is_sub_account`** (`l1/src/sub_account.rs`): `0x366b040..0x366b0c6` (`134 B`, `127/134` raw-equal, 2 reloc slots).

### `risk` (`8` FDEs, `1,476 B`, `1,325/1,476 = 89.77%` raw-equal)
3. **`SpotClearinghouse::check_zero_balances`** (`l1/src/spot_clearinghouse/spot_clearinghouse.rs`): `0x3bf48e0..0x3bf4948` (`104 B`, `96/104` raw-equal, 2 reloc slots).
4. **`SpotClearinghouse::user_state`** (`l1/src/spot_clearinghouse/spot_clearinghouse.rs`): `0x3bf4c30..0x3bf4ca2` (`114 B`, `83/114` raw-equal, 8 reloc slots).
5. **`SpotClearinghouse::burn_user_token`** (`l1/src/spot_clearinghouse/spot_clearinghouse.rs`): `0x3bfa340..0x3bfa3f4` (`180 B`, `160/180` raw-equal, 6 reloc slots).
6. **`SpotClearinghouse::validate_token_before_genesis`** (`l1/src/spot_clearinghouse/spot_clearinghouse.rs`): `0x3bfa810..0x3bfa90d` (`253 B`, `246/253` raw-equal, 2 reloc slots).
7. **`SpotClearinghouse::has_user_state`** (`l1/src/spot_clearinghouse/spot_clearinghouse.rs`): `0x3bfcf60..0x3bfd012` (`178 B`, `172/178` raw-equal, 2 reloc slots).
8. **`Clearinghouse::scale_u64_by_rate`** (`l1/src/clearinghouse/clearinghouse.rs`, `Clearinghouse + 0x4e0` rate scaler invoked cross-CGU via `.got` from `impl_spot_deploy.rs`): `0x44811d0..0x44812b0` (`224 B`, `201/224` raw-equal, 6 reloc slots).
9. **`Clearinghouse::scale_i64_by_rate`** (`l1/src/clearinghouse/clearinghouse.rs`, `Clearinghouse + 0x4e0` rate scaler invoked cross-CGU via `.got` from `impl_vault.rs`): `0x44812b0..0x4481374` (`196 B`, `172/196` raw-equal, 6 reloc slots).
10. **`Clearinghouse::check_oracle_price_deviation`** (`l1/src/clearinghouse/clearinghouse.rs`): `0x4488300..0x44883e3` (`227 B`, `195/227` raw-equal, 8 reloc slots).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-risk-exchange-vaults-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_risk_exchange_vaults_logic_byte_matches_115 -v
(cd research/work-items/RE-007-node115-risk-exchange-vaults-logic-byte-matches && sha256sum -c MANIFEST.sha256)
```
