# RE-010: Node #115 Complete `l1-shared` (`l1/*` Residual Helpers) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `l1-shared` (all `l1/src/*.rs` files classified under `l1/*` in `research/components.json` after earlier `l1/*` components — Stream E2-B / `RE-010`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `l1-shared` source file (**8/8**), **every** `.data.rel.ro` `Location` struct (**13/13**), **every** `.text` FDE referencing those `Location` structs (**39/39 unique FDEs = 142,060 bytes**), and **14 core `l1-shared` business-logic FDEs** (`9,256 bytes`, **53 unique FDEs / 151,316 bytes** combined), backed by independently authored behavioral Rust in `src/l1-shared` (wired into `src/action-wire`, `src/exchange`, and `src/hl-node`).

## Exhaustive 8-File Node #115 Inventory

| # | Observed `#115` Source File | Locations | Location FDEs | Binary-Backed Semantics Closed in `src/l1-shared` |
| --- | --- | ---: | ---: | --- |
| 1 | `l1/src/agent_tracker.rs` | 1 (`0x64764e0` L137:48) | 1 (`0x3be79a0`, 1,241 B) | `IndexMap` `0x38`-byte agent entries + `node115_agent_erase_state` (`l1_shared::agent_erase`) |
| 2 | `l1/src/bole/user_state.rs` | 2 (`0x644d5d8`, `0x64aa2a8` L239:44) | 8 (`51,060 B`) | `state_guards::classify_bole_user_lookup` (status `2` empty / status `3` code `0x0c` missing reserve) |
| 3 | `l1/src/chain_ext.rs` | 1 (`0x6493830` L109:29) | 1 (`0x46f3fc0`, 240 B) + 3 inits (`2,904 B`) | `chain_ext::chain_addresses` (4-arm jump table `0x7d92d4`; Local panic `"invalid chain"`, Sandbox/Mainnet/Testnet sorted 4-address sets) |
| 4 | `l1/src/hyperliquidity.rs` | 1 (`0x646e4c8` L360:29) | 1 (`0x38bc000`, 2,705 B) + 4 helpers (`1,698 B`) | `hyperliquidity` (`price_tick`, `generate_ladder`, `funding_cost`, `market_cap_in_band`, `validate_hyperliquidity_seed`) |
| 5 | `l1/src/nonce_set.rs` | 1 (`0x6483ff8` L141:13) | 5 (`1,685 B`) + 4 helpers (`1,959 B`) | `nonce_set::NonceRing` (7-rule admission `0x4228080`, 19 expanded addresses `0x4228310`, `NonceSetDe` strictly-ascending `from_deserialized` `0x4227d30`) |
| 6 | `l1/src/raw_signature_tracker.rs` | 2 (`0x6468b38`, `0x64a7f08` L231:9) | 10 (`40,149 B`) | `state_guards::raw_signature_bucket_in_bounds` (`0x368b341` `cmp rax, 0x897` = 2,199 bound) |
| 7 | `l1/src/simulate_panic.rs` | 1 (`0x6492ef0` L10:13) | 6 (`41,469 B`) | `state_guards::check_simulate_panic_gate` (`0x2bdf881` `"explicit panic"` at `0x7db393`) |
| 8 | `l1/src/utils.rs` | 4 (L19:42 ×2, L28:43, L121:5) | 7 (`3,511 B`) | `utils::{keccak256, sha256, hard_link_and_replace}` (Keccak `0x88`/`0x01`, SHA-256 IV `0x457ae0`, `utils_hard_link_and_replace/` same-`(dev,ino)` fast path) |

Plus `decimal_scaler` (`0x421e9d0`, `0x5c43c60`, `0x43099f0` = `2,695 B`) and all 5 registered sibling micro-crates (`node115-agent-erase-state`, `node115-event-context-id`, `node115-nonce-key-decode`, `node115-slice20-equal`, `node115-token-id`).

## Honest Gate Status & Limitations

- **Mapped / Built / Behavior**: All 8 observed `#115` files, 13 Locations, 39 Location FDEs, 14 business FDEs, 11 instruction anchors, 4 `.rodata` literals, and 5 `.rodata` constants are machine-verified against the pinned binary; `src/l1-shared` (`#![forbid(unsafe_code)]`, 0 external deps, clippy `-D warnings` clean) passes behavioral/boundary tests covering every file.
- **Identity**: `identity` remains `false`; compiled-byte matching is tracked separately in `research/byte-windows.json` and compiled-byte packets (no whole-component byte identity is claimed here).
- **Static-only boundary**: The captured binary was inspected statically and was never executed or emulated.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-010-node115-l1-shared-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_l1_shared_closure_115 -v
(cd research/work-items/RE-010-node115-l1-shared-closure && sha256sum -c MANIFEST.sha256)
(cd src/l1-shared && cargo test --offline && cargo clippy --offline --all-targets -- -D warnings)
```
