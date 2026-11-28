# RE-010: Node #115 `l1-shared` & `action-wire` Pure Business-Logic Compiled-Byte FDE Matches

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: `l1-shared` (`l1/src/{hyperliquidity,chain_ext,nonce_set}.rs`) and `action-wire` (`l1/src/action/{mod,withdraw3,vault_transfer,batch_modify}.rs`, `l1/src/action_delayer.rs`).
- **Build profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, edition `2021`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#![forbid(unsafe_code)]`:
  - `std_logic/`: pure `std` + 1 local cross-crate stub (`e2b_lib.rs`), `0` external crates (`14` FDEs / `2,447 B`).
  - `jem_serde/`: locked offline `tikv-jemallocator = "=0.6.0"`, `serde = "=1.0.229"`, `serde_json = "=1.0.154"`, `rmp-serde = "=1.3.1"` (`21/21` permissive SPDX licenses in `licenses.json`, `3` FDEs / `979 B`).

## Verified Disjoint First-Party Business-Logic FDE Matches (17 windows / 3,426 B)

All **17** windows are strictly first-party defining-crate business logic (`0` `core::`/`alloc::`/`std::`/third-party attribution, `0` `drop_in_place`), **100.00% relocation-qualified** via `tools/byte_progress.compare` (`0` non-relocation byte diffs, `0` GOTPCRELX/TLS relaxations, standard 4-byte `PC32`/`PLT32`/`GOTPCREL` relocations only), **3,082 / 3,426 = 89.96% raw-equal** (`1` window 100.00% raw-equal with `0` relocations), exact in `work/index/node-115-fde.tsv`, binary-anchor verified, and strictly disjoint internally, against `research/byte-windows.json` (Wave-7 consolidation-safe), and across every sibling compiled-byte / census packet across all VA key spellings:

### `l1-shared` (`7` FDEs / `2,023 B`, `1,743 / 2,023 = 86.16%` raw-equal)

| # | Window ID | Node #115 FDE | Bytes | Raw-Equal | Function & Verified Binary Anchor |
| --- | --- | --- | ---: | ---: | --- |
| 1 | `node115-action-logic-hl-funding-cost` | `0x38bcb80..0x38bcbee` | 110 | 110 (100.0%) | `hyperliquidity::funding_cost` (`0` relocs; `i64::MAX - 1` `0x7ffffffffffffffe` cap check; CGU `l1/src/hyperliquidity.rs:360:29`) |
| 2 | `node115-action-logic-chain-ext-config` | `0x46f3fc0..0x46f40b0` | 240 | 164 (68.3%) | `ChainExt::chain_config` (`Location` `l1/src/chain_ext.rs:109:29`, `.rodata 0x7de6a6` `"invalid chain"`) |
| 3 | `node115-action-logic-nonce-expanded-set-b` | `0x421a3c0..0x421a51b` | 347 | 283 (81.6%) | `nonce_set::is_expanded_set_b` (8 exact 20-byte SIMD `.rodata` addresses in `l1/src/nonce_set.rs`) |
| 4 | `node115-action-logic-nonce-expanded-set-a` | `0x421a520..0x421a67b` | 347 | 283 (81.6%) | `nonce_set::is_expanded_set_a` (8 exact 20-byte SIMD `.rodata` addresses in `l1/src/nonce_set.rs`) |
| 5 | `node115-action-logic-nonce-set-de-json-1` | `0x2923da0..0x2923ee1` | 321 | 297 (92.5%) | `<NonceSet as Deserialize>::deserialize` (JSON copy #1; `Location` `l1/src/nonce_set.rs:141:13`, `.rodata 0x7c958c` `"nonce invariant"`) |
| 6 | `node115-action-logic-nonce-set-de-json-2` | `0x4227e90..0x4227fd1` | 321 | 297 (92.5%) | `<NonceSet as Deserialize>::deserialize` (JSON copy #2; `Location` `l1/src/nonce_set.rs:141:13`, `.rodata 0x7c958c` `"nonce invariant"`) |
| 7 | `node115-action-logic-nonce-set-de-rmp-1` | `0x4227d30..0x4227e81` | 337 | 309 (91.7%) | `<NonceSet as Deserialize>::deserialize` (MessagePack `rmp_serde`; `Location` `l1/src/nonce_set.rs:141:13`, `.rodata 0x7c9582` `"NonceSetDe"`) |

### `action-wire` (`10` FDEs / `1,403 B`, `1,339 / 1,403 = 95.44%` raw-equal)

| # | Window ID | Node #115 FDE | Bytes | Raw-Equal | Function & Verified Binary Anchor |
| --- | --- | --- | ---: | ---: | --- |
| 8 | `node115-action-logic-withdraw3-send-1` | `0x246cd10..0x246cdc8` | 184 | 177 (96.2%) | `Withdraw3Action::send_to_exchange` (#1; `Location` `l1/src/action/withdraw3.rs:17:22`) |
| 9 | `node115-action-logic-withdraw3-send-2` | `0x59da3e0..0x59da498` | 184 | 177 (96.2%) | `Withdraw3Action::send_to_exchange` (#2; `Location` `l1/src/action/withdraw3.rs:17:22`) |
| 10 | `node115-action-logic-withdraw3-send-3` | `0x59da4a0..0x59da558` | 184 | 177 (96.2%) | `Withdraw3Action::send_to_exchange` (#3; `Location` `l1/src/action/withdraw3.rs:17:22`) |
| 11 | `node115-action-logic-vault-transfer-send-1` | `0x283c6b0..0x283c768` | 184 | 177 (96.2%) | `VaultTransferAction::send_to_exchange` (#1; `Location` `l1/src/action/vault_transfer.rs:27:18`) |
| 12 | `node115-action-logic-vault-transfer-send-2` | `0x532f980..0x532fa38` | 184 | 177 (96.2%) | `VaultTransferAction::send_to_exchange` (#2; `Location` `l1/src/action/vault_transfer.rs:27:18`) |
| 13 | `node115-action-logic-vault-transfer-send-3` | `0x532fa40..0x532faf8` | 184 | 177 (96.2%) | `VaultTransferAction::send_to_exchange` (#3; `Location` `l1/src/action/vault_transfer.rs:27:18`) |
| 14 | `node115-action-logic-action-delay-priority` | `0x36c2fa0..0x36c2ff1` | 81 | 77 (95.1%) | `Action::delay_priority` (92-entry `.rodata` jump table `0x79ab60`) |
| 15 | `node115-action-logic-action-is-not-exempt` | `0x36c3000..0x36c3028` | 40 | 36 (90.0%) | `Action::is_not_exempt` (92-entry `.rodata` jump table `0x79acd0`) |
| 16 | `node115-action-logic-action-is-alo-only` | `0x36c5680..0x36c5711` | 145 | 134 (92.4%) | `Action::is_alo_only` (92-entry `.rodata` jump table `0x79b400`) |
| 17 | `node115-action-logic-batch-modify-delay-secs` | `0x37b9ba0..0x37b9bc1` | 33 | 30 (90.9%) | `BatchModifyAction::delay_secs` (`cmp dword [rsi+0x50], 3` + stride `0x38` tail-jump) |

## Honest Scope & Limitations

- These 17 FDEs establish selected compiled-byte equivalence for specific `l1-shared` and `action-wire` functions only; they do **not** claim whole-component byte identity (`identity` remains `false`).
- The captured node #115 binary was inspected statically and was never executed or emulated.
- `research/byte-windows.json` and `research/progress.json` are untouched by this packet (Wave-7 consolidation-ready under prefix `node115-action-logic-*`).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-010-node115-action-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 python3 research/work-items/RE-010-node115-action-logic-byte-matches/verify.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_action_logic_byte_matches_115 -v
(cd research/work-items/RE-010-node115-action-logic-byte-matches && sha256sum -c MANIFEST.sha256)
```
