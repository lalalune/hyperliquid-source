# RE-007: Node #115 Complete `vaults` (`l1/src/vault/*`, `l1/src/sub_account.rs`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `vaults` (`l1/vault/*`, `l1/sub_account.rs` — Stream E2 / `RE-007`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `vaults` source file (**2/2**: `l1/src/sub_account.rs`, `l1/src/vault/mod.rs`), **every** `.data.rel.ro` `Location` struct (**9/9**), **every** `.text` FDE referencing those `Location` structs (**5/5 unique FDEs = 17,319 bytes**), and **every** companion CGU business-logic FDE in `l1/src/sub_account.rs` (`0x366a620..0x366b4f9`) and `l1/src/vault/mod.rs` (`0x44a9430..0x44b04b6`) plus `checked_ratio` (`0x14ca350`) (**15/15 disjoint companion FDEs = 15,322 bytes**, **20 unique FDEs / 32,641 bytes** combined).

## Final `vaults` Business Routines Closed Here

1. **`SubAccountTracker::modify_sub_account` (`0x366b0d0..0x366b350`, `640 B`)**:
   - Enforces outer name byte bound `<= 100` (`0x366b1a6`: `cmp r8, 0x64` -> tag `0x158`), delegates to the inner label guard `0x366b350` (`1..=16` UTF-8 bytes -> `0xe8`, case-insensitive uniqueness -> `0xe6`), locates the target 20-byte sub-account address in the master's list (`pcmpeqb`; missing -> tag `0xeb` at `0x366b22e`), and renames in place returning `0x1a2`.
2. **`Vault::new` (`0x44ae320..0x44ae805`, `1,253 B`)**:
   - Validates `initial_usd < 0x0ccc_cccc_cccc_cccc` (`0x44ae34b` -> `0x154`), `initial_usd >= 100_000_000` (`$100.00`, `0x44ae35a` -> `0x01`), name length `<= 100` (`0x158`) and `3..=50` (`0x03`/`0x04`), description length `<= 250` (`0x158`) and `>= 10` (`0x05`).
   - Selects chain lockup duration from `.rodata` table `0x454110` (`[20.0, 86400.0]`: `86400.0 s` on Mainnet `chain_id == 3`, `20.0 s` otherwise) and defaults leader commission to `0.1` (`0x4593e0` = 10%, or `0.0` when commission-exempt).
3. **`Vault::vault_equity` (`0x44aad40..0x44ab017`, `727 B`) & `Vault::max_withdrawable` (`0x44abfb0..0x44ac60e`, `1,630 B`)**:
   - `vault_equity` calls `vault_amount` (`0x44a9430`) on the vault and saturating-sums all child vault equities when `vault_tag == 2` (`0x44aad66`: `cmpl $0x2, (%r15)`).
   - `max_withdrawable` computes `sat_trunc_i64(share_fraction * total_equity)` and, for the vault leader, reserves at least `max($100, follower_equity * (0.05 / 0.95))` using exact `.rodata` constant `0x459240` (`0.052631578947368425`, `0x44ac45d`) and `$100` threshold (`0x44ac4bf`).

## Complete `vaults` Acceptance Inventory

- **Mapped**: 2/2 `vaults` source files, 9/9 `Location` structs, 5/5 Location-referencing FDEs (`17,319 B`) + 15/15 companion business FDEs (`15,322 B`) = **20 unique FDEs (`32,641 B`)** verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/vaults` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/hl-node`) combines all 6 registered `vaults` micro-crates (`node115-vault-identity-guards`, `node115-vault-create-context`, `node115-quantity-source`, `node115-vault-address`, `node115-vault-redistribution`, `node115-vault-weight-update`) with full binary-verified implementations of `checked_ratio` (`0x14ca350`), `vault_amount` (`0x44a9430`) & base-conversion (`0x3beb980`), `vault_equity` (`0x44aad40`), `Vault::distribute` (`0x44a97b0`), `Vault::withdraw_gate` (`0x44ab4a0`), `Vault::max_withdrawable` (`0x44abfb0`), `Vault::new` (`0x44ae320`), `Vault::move_core` (`0x44ae810`) + both 8-address protected vault sets (`0x421a3c0`/`0x421a520`), `Vault::share_split` (`0x44af2f0`), and `SubAccountTracker` (`0x366a620`, `0x366b0d0`, `0x366b350`).
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proofs currently cover `RE-007-node115-stream-e2-debug-byte-matches` (`2w / 386 B` `vaults` `Debug::fmt` FDEs) plus `RE-007-node115-stream-e2-byte-matches` (`vaults` visitor FDEs).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-vaults-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_vaults_closure_115 -v
(cd research/work-items/RE-007-node115-vaults-closure && sha256sum -c MANIFEST.sha256)
```
