# RE-007: node #115 `Vault::distribute` (`0x44a97b0`) & Complete `l1/src/vault/mod.rs` FDE/Location Map

- Component ID: `vaults` (`RE-007`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: **observation** for all 6 core vault FDE extents (16,713 B total `.text`), all 8 relocated `l1/src/vault/mod.rs` panic `Location` records, `$10.00` minimum distribution immediate (`0x989680`), error/ok tags (`0x12`, `0x13`, `0x14`, `0x34`, `0x1a2`), and diagnostic strings (`0x7d2afa`, `0x43f417`); **inference** for reconstructed Rust API (`distribute_vault`, `VaultFollowerDistributeState`, `VaultDistributeOutcome`) implemented in `src/vaults/src/distribute.rs`.
- Remaining unknowns: child-vault sweep & clearinghouse ledger event serialization callees (`0x4472ea0`, `0x3ccf5d0`, `0x3f152c0`) invoked as side effects inside `0x44a97b0`.

## Evidence (node #115 static observations)

| Function VA (size) | Role & `l1/src/vault/mod.rs` panic `Location`s |
| --- | --- |
| `0x14ca350..0x14ca3e4` (148 B) | `checked_ratio`: finite + `(-1e-15, 0) -> 0` clamp + denominator `>= 1e-15`. |
| `0x44a9430..0x44a97af` (895 B) | `vault_amount`: equity sum over parent + child vaults. |
| `0x44a97b0..0x44aad40` (5,520 B) | `Vault::distribute`: `mod.rs:517:50` (`0x648c110`), `mod.rs:525:50` (`0x648c128`), `mod.rs:526:79` (`0x648c140`); enforces `>= 0x989680` ($10 USDC -> `0x13`), `<= max_distributable` (`0x12`), close-all `vault_equity == withdrawable` (`0x14`), balance `>= usd` (`0x34`), per-follower profit-share commission (`leader_commission` at `vault+0x70`), non-positive user ledger warning (`0x7d2afa`, `0x43f417`), and residual settlement returning `0x1a2`. |
| `0x44ab4a0..0x44abfaf` (2,831 B) | `evaluate_withdraw_gate`: `mod.rs:618:93` (`0x648c158`), `mod.rs:623:71` (`0x648c170`). |
| `0x44ae810..0x44af2e1` (2,769 B) | `vault_move_core`: `mod.rs:382:34` (`0x648c188`), `mod.rs:401:58` (`0x648c1a0`). |
| `0x44af2f0..0x44b04b6` (4,550 B) | `execute_vault_split`: `mod.rs:745:58` (`0x648c1b8`). |

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_vault_distribute_and_map_115
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-vault-distribute-and-map
(cd research/work-items/RE-007-node115-vault-distribute-and-map && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/risk-exchange \
  cargo test --offline --locked --manifest-path src/vaults/Cargo.toml
```
