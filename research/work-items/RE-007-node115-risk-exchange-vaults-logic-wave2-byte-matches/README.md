# RE-007: Node #115 Risk & Exchange Pure First-Party Logic Wave 2 Byte Matches

## Summary

Live-compiled, zero-dependency, `#![forbid(unsafe_code)]` Rust 1.95.0 byte-identity verification of **11 strictly disjoint pure first-party business-logic FDEs** (`2,919` bytes total; `2,863 / 2,919 = 98.08%` raw-equal, `0` non-relocation diffs, `0` relaxations, `0` overlaps with `research/byte-windows.json` or any sibling work-item packet) in Linux x86-64 `hl-node` #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler**: `rustc 1.95.0 (59807616e 2026-04-14)` (`--edition=2021 -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C codegen-units=1`, zero external dependencies)
- **Wave-8 consolidation prefix**: `node115-risk-exch-w2-*`

## Component Breakdown

| Component | Windows | Total Bytes | Raw-Equal Bytes | Raw-Equal % |
| --- | ---: | ---: | ---: | ---: |
| `risk` | 3 | 569 | 556 | 97.72% |
| `exchange` | 8 | 2,350 | 2,307 | 98.17% |
| **Total** | **11** | **2,919** | **2,863** | **98.08%** |

## Verified FDE Windows & CGU Provenance

| # | Component | Symbol | Node #115 VA Range | Size | Raw-Eq | Relocs | Semantic Role & CGU Evidence |
| ---: | --- | --- | --- | ---: | ---: | ---: | --- |
| 1 | `risk` | `risk_bole_leg_shares_248` | `0x3692f30..0x3693028` | 248 | 245 | 1 | `BoleUserState::leg_shares` (`l1/src/bole/user_state.rs`, mapped to `risk` in `research/byte-windows.json`) |
| 2 | `risk` | `risk_spot_user_balance_253` | `0x3c00800..0x3c008fd` | 253 | 250 | 1 | `SpotUserState::balance` (`l1/src/spot_clearinghouse/user_state.rs`, CGU neighbors at `l1/src/qtys/impl_wei.rs:6:1`) |
| 3 | `risk` | `risk_ch_user_field48_68` | `0x447e7c0..0x447e804` | 68 | 61 | 2 | `Clearinghouse::user_field48` (`l1/src/clearinghouse/clearinghouse.rs`, CGU neighbors at `l1/src/clearinghouse/oracle/oracle.rs:433:18`) |
| 4 | `exchange` | `exch_spot_deploy_set_token_annotation_335` | `0x2c543a0..0x2c544ef` | 335 | 327 | 2 | `Exchange<A>::spot_deploy_set_token_annotation` copy 1 (`l1/src/exchange/impl_spot_deploy.rs`; immediately follows `0x2c54260` EVM contract deploy, calls GOT `0x3c4a260` `"can only change token annotation once per day"`) |
| 5 | `exchange` | `exch_spot_deploy_set_token_annotation_335` | `0x55c61c0..0x55c630f` | 335 | 329 | 2 | `Exchange<A>::spot_deploy_set_token_annotation` copy 2 (`Exchange<Aux>` monomorphization in `l1/src/exchange/impl_spot_deploy.rs`) |
| 6 | `exchange` | `exch_spot_deploy_set_token_annotation_335` | `0x55c6310..0x55c645f` | 335 | 329 | 2 | `Exchange<A>::spot_deploy_set_token_annotation` copy 3 (`Exchange<Aux>` monomorphization in `l1/src/exchange/impl_spot_deploy.rs`) |
| 7 | `exchange` | `exch_spot_deploy_set_deploy_state_flag_293` | `0x2c56810..0x2c56935` | 293 | 289 | 1 | `Exchange<A>::spot_deploy_set_deploy_state_flag` copy 1 (`l1/src/exchange/impl_spot_deploy.rs`; immediately precedes `0x2c56940` `"cannot use USDC as base token"` and `0x2c56a80` `"genesis already happened"`) |
| 8 | `exchange` | `exch_spot_deploy_set_deploy_state_flag_293` | `0x55cabc0..0x55cace5` | 293 | 290 | 1 | `Exchange<A>::spot_deploy_set_deploy_state_flag` copy 2 (`Exchange<Aux>` monomorphization) |
| 9 | `exchange` | `exch_spot_deploy_set_deploy_state_flag_293` | `0x55cacf0..0x55cae15` | 293 | 290 | 1 | `Exchange<A>::spot_deploy_set_deploy_state_flag` copy 3 (`Exchange<Aux>` monomorphization) |
| 10 | `exchange` | `exch_counted_exchange_entry_dispatch_233` | `0x2c766e0..0x2c767c9` | 233 | 225 | 2 | `Exchange<A>::counted_exchange_entry_dispatch` copy 1 (`l1/src/exchange/` CGU alongside `l1/src/exchange/end_block.rs:194:32`; saturating attempt/success counters at `+0xb40`/`+0xb48`, GOT calls to `0x3be7e80` and `0x4228310`) |
| 11 | `exchange` | `exch_counted_exchange_entry_dispatch_233` | `0x560dca0..0x560dd89` | 233 | 228 | 2 | `Exchange<A>::counted_exchange_entry_dispatch` copy 2 (`Exchange<Aux>` monomorphization; third copy `0x560dbb0` excluded for 0-overlap cleanliness vs `RE-017-abci-block-root-115`) |

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-risk-exchange-vaults-logic-wave2-byte-matches/verify.py --self-test
(cd research/work-items/RE-007-node115-risk-exchange-vaults-logic-wave2-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_risk_exchange_vaults_logic_wave2_byte_matches_115 -v
```
