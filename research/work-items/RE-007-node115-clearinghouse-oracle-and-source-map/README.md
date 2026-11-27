# RE-007: node #115 Reference Oracle Monitor (`0x366f900`), `OracleKind` (`0x3db4e40`), and Complete 27-File Non-Exchange Stream E2 Source Map

- Component ID: `risk` (`RE-007`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: **observation** for all 5 FDE extents (`0x3db4e40`, `0x366f900`, `0x4205370`, `0x283c6b0`, `0x246cd10`), `.rodata` float constants `-1.0` (`0x458dc8`) and `1e9` (`0x458d50`), 4 instruction anchors, and all 27 distinct non-exchange Stream E2 `l1/src/*` source files anchored via relocated `.data.rel.ro` panic `Location` records (combined with `RE-010-node115-exchange-orchestration-map`'s 15 `l1/src/exchange/*.rs` files, all 42 Stream E2 `l1/src/*` source files are anchored); **inference** for reconstructed Rust API (`OracleKind`, `ReferenceOraclePolicy`, `ReferenceOracleTracker`, `evaluate_reference_oracle`) implemented in `src/clearinghouse/src/reference_oracle.rs`.
- Remaining unknowns: exact semantic names of `OracleKind` variants (`0`, `1`, `2`) beyond the 3-variant count, and full inner policy loader `0x64e8cc0`.

## Evidence (node #115 static observations)

| Function VA (size) | Observed #115 behavior & anchors |
| --- | --- |
| `0x3db4e40..0x3db50ed` (685 B) | `OracleKind` 3-variant collector (`cmpq $0x3, %rax` at `0x3db4e81`, `l1/src/clearinghouse/oracle/oracle_kind.rs:3:105`). |
| `0x366f900..0x366fbe4` (740 B) | `ReferenceOracle::evaluate` (`l1/src/clearinghouse/oracle/reference_oracle.rs:211:25`): computes `dev = (max(ref, cur) / min(ref, cur)) + (-1.0)` (`0x458dc8`), clears violation tracker when `threshold.max(0.0) > dev`, else tracks `(first, last)` timestamps (`0x458d50 = 1e9`), fires severity-8 alert (`0x366fbc5`) when `alert_enabled && elapsed > max_duration_secs`, returns `alert_enabled`. |
| `0x4205370..0x4205dde` (2,670 B) | `l1/src/clearinghouse/position_map.rs:274:61`. |
| `0x283c6b0..0x283c768` (184 B) | `l1/src/action/vault_transfer.rs:27:18` action-result wrapper (`0x1a2` -> `0x0e` else `0x0f`). |
| `0x246cd10..0x246cdc8` (184 B) | `l1/src/action/withdraw3.rs:17:22` action-result wrapper (`0x1a2` -> `0x0e` else `0x0f`). |

### Complete 27-File Non-Exchange Stream E2 Source Map

Anchored in `evidence.json`:
- `l1/src/clearinghouse/` (10 files): `cl_trait.rs`, `clearinghouse.rs`, `impl_first_dex.rs`, `margin_table.rs`, `oracle/oracle.rs`, `oracle/oracle_kind.rs`, `oracle/reference_oracle.rs`, `position.rs`, `position_map.rs`, `user_state.rs`
- `l1/src/spot_clearinghouse/` (4 files): `cl_trait.rs`, `impl_outcome.rs`, `spot_clearinghouse.rs`, `types.rs`
- `l1/src/bole/` (1 file): `user_state.rs`
- `l1/src/action/` (5 files): `rmp_signable.rs`, `user_outcome.rs`, `vault_transfer.rs`, `vote_global.rs`, `withdraw3.rs`
- `l1/src/dex_registry/` (3 files): `clearinghouses.rs`, `dex_registry.rs`, `perp_dex.rs`
- `l1/src/vault/` & shared L1 (4 files): `vault/mod.rs`, `sub_account.rs`, `nonce_set.rs`, `hyperliquidity.rs`

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_clearinghouse_oracle_and_source_map_115
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map
(cd research/work-items/RE-007-node115-clearinghouse-oracle-and-source-map && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/clearinghouse/Cargo.toml
```
