# RE-011: Node #115 Stream F First-Party Logic Compiled-Byte FDE Matches (`bridge`, `evm`, `evm-rpc`)

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Scope**: 23 strictly disjoint, non-visitor first-party `.text` FDEs (**20,833 bytes**, **20,150 / 20,833 = 96.72%** raw-equal, **0 non-relocation byte diffs**, **0 `Visitor::expecting` padding**) live-compiled from clean-room `#![forbid(unsafe_code)]`, zero-external-dependency Rust (`lib.rs`) under `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes -C codegen-units=1 --emit=obj`.

## Summary by Component

| Component | Type & Method | FDEs | Total Bytes | Notes |
| --- | --- | ---: | ---: | --- |
| `bridge` | `Bridge2::FieldVisitor::visit_bytes` (RMP) | 3 | 6,921 | `0x28618e0`, `0x4442e00`, `0x5ae3260` (2,307 B each; 15 fields + `__Ignore`) |
| `bridge` | `Bridge2::FieldVisitor::visit_str` (tag0 & RMP) | 5 | 3,350 | `0x28621f0`, `0x2862490`, `0x4443710`, `0x44439b0`, `0x5ae3b70` (670 B each) |
| `bridge` | `EthEventId::FieldVisitor::visit_str` (tag0 & RMP) | 5 | 1,255 | `0x28657c0`, `0x28658c0`, `0x4446940`, `0x4446a40`, `0x5ae4780` (251 B each; `b`/`t`/`e`/`i`/`h` + long aliases) |
| `evm` | `HyperEvm::FieldVisitor::visit_bytes` (RMP) | 3 | 5,544 | `0x299c930`, `0x4339e20`, `0x5472610` (1,848 B each; 15 fields + `__Ignore`) |
| `evm` | `HyperEvm::FieldVisitor::visit_str` (tag0 & RMP) | 5 | 3,145 | `0x299d070`, `0x299d2f0`, `0x433a560`, `0x433a7e0`, `0x5472d50` (629 B each) |
| `evm-rpc` | `EthCallOverrides::FieldVisitor::visit_str` | 1 | 264 | `0x29aee50` (`request`, `blockId`/`block_id`, `stateOverrides`/`state_overrides`, `blockOverrides`/`block_overrides`) |
| `evm-rpc` | `AccountOverride::FieldVisitor::visit_str` | 1 | 354 | `0x2745310` (`balance`, `nonce`, `code`, `state`, `stateDiff`, `MovePrecompileToAddress`/`movePrecompileToAddress`, `unknown_field`) |
| **Total** | **5 first-party Stream F types** | **23** | **20,833** | **Zero overlaps** across `research/byte-windows.json` and all sibling byte-match / gate-closure packets |

## Structural Findings Anchored by Byte Identity

1. **`Bridge2` (`bridge`, 15 fields)**: exact field order `eth_id_to_deposit_votes`, `finished_deposits_data`, `dvp`, `dvpd`, `dvs`, `lfd`, `withdrawal_signatures`, `withdrawal_finalized_votes`, `finished_withdrawal_to_time`, `validator_set_signatures`, `validator_set_finalized_votes`, `bal`, `last_pruned_deposit_block_number`, `oaw`, `r` (plus `__Ignore`), proving both RMP `visit_bytes` (`ErrTag9` 9-variant niche -> tag `0x09`) and `visit_str` (`ErrTag0` tag `0x00` and `ErrTag9` tag `0x09`) codegen.
2. **`EthEventId` (`bridge`, 5 fields)**: proves exact 1-character compact wire renames (`b`, `t`, `e`, `i`, `h`) paired with full aliases (`block_number`, `tx_index`, `event_type`, `event_index`, `tx_hash`) compiled into a two-level PIC jump table (`251 B`).
3. **`HyperEvm` (`evm`, 15 fields)**: exact field order `state2`, `latest_block2`, `small_block_context`, `big_block_context`, `is_initialized`, `l1_to_evm_native_token_queue`, `l1_to_evm_erc20_queue`, `l1_transfers_enabled`, `disabled_core_writer_actions`, `put`, `ul`, `ub`, `ft`, `mrb`, `dt` (plus `__Ignore`), proving both RMP `visit_bytes` (`1,848 B`) and `visit_str` (`629 B`).
4. **`EthCallOverrides` & `AccountOverride` (`evm-rpc`)**: proves HyperEVM JSON-RPC override deserialization, including Hyperliquid's custom `MovePrecompileToAddress` / `movePrecompileToAddress` account-override field with `#[serde(deny_unknown_fields)]` cold `unknown_field` dispatch.

## Verification

```bash
(cd research/work-items/RE-011-node115-stream-f-logic-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-011-node115-stream-f-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_f_logic_byte_matches_115 -v
```
