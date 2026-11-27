# RE-010: Node #115 Complete `action-wire` (`l1/action/*`, `l1/action_delayer.rs`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `action-wire` (`l1/action/*`, `l1/action_delayer.rs` — Stream E2-B / `RE-010`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `action-wire` source file (**5/5**), **every** `.data.rel.ro` `Location` struct (**13/13**), **every** `.text` FDE referencing those `Location` structs (**15/15 unique FDEs = 147,163 bytes**), and **6 core `action-wire` business-logic FDEs** (`38,508 bytes`, **21 unique FDEs / 185,671 bytes** combined), plus `.rodata` `ActionDelayer`/`DelayedAction` schema witnesses, backed by independently authored behavioral Rust in `src/action-wire` (wired into `src/action-dispatch`, `src/exchange`, and `src/hl-node`).

## Exhaustive 5-File + `ActionDelayer` Node #115 Inventory

| # | Observed `#115` Source File | Locations | Location FDEs | Binary-Backed Semantics Closed in `src/action-wire` |
| --- | --- | ---: | ---: | --- |
| 1 | `l1/src/action/rmp_signable.rs` | 3 (L14:55 ×3) | 3 (`0x36aa9a0`, `0x3c267e0`, `0x421bb70`; `3,430 B`) | `rmp_signable::{connection_id_preimage, connection_id}` (`msgpack || be64(nonce) || (0x00 \| 0x01 || vault) || opt(0x00 || be64(expires))` -> Keccak-256) |
| 2 | `l1/src/action/user_outcome.rs` | 4 (L55:56 ×2, L59:26 ×2) | 3 (`0x283b5b0`, `0x567c830`, `0x567d220`; `7,623 B`) | `rmp_signable::check_user_outcome_entry` (disabled `0x92` -> blocked `0x193`/subcode `7` -> missing user `0x15`) |
| 3 | `l1/src/action/vault_transfer.rs` | 2 (L27:18 ×2) | 3 (`0x283c6b0`, `0x532f980`, `0x532fa40`; `552 B`) | `rmp_signable::fold_action_result` (`0x1a2 -> 0x0e`, else `0x0f` + `0x70`-byte payload copy) |
| 4 | `l1/src/action/vote_global.rs` | 2 (L1504:40 ×2) | 3 (`0x28cd7a0`, `0x538cd30`, `0x5397b50`; `135,006 B`) | `variants::VOTE_GLOBAL_NICHE_INDEX` (index `20`, niche tag `< 0x86`) + Location witness `0x28d467a` |
| 5 | `l1/src/action/withdraw3.rs` | 2 (L17:22 ×2) | 3 (`0x246cd10`, `0x59da3e0`, `0x59da4a0`; `552 B`) | `rmp_signable::fold_action_result` (`0x1a2 -> 0x0e`, else `0x0f` + `0x70`-byte payload copy) |
| — | `l1/src/action_delayer.rs` (0 Locations) | 0 | `.rodata` witness | `rmp_signable::DelayedActionRecord` (`struct ActionDelayer with 6 elements` at `0x5c9a34`, `struct DelayedAction` at `0x5c9a83`) |

Plus 6 core business FDEs (`38,508 B`): EIP-712 domain separator (`0x169e950`), EIP-712 signing digest (`0x44e5db0`), 92-variant method dispatcher (`0x36c3180`), 92-variant serializer (`0x2bce570`), 418-tag error Display formatter (`0x46ef710`), and template decoder (`0x1680500`), backed by `src/action-wire/src/{eip712,error_display,rmp_signable,variants}.rs` and all 11 registered sibling micro-crates in `research/components.json`.

## Honest Gate Status & Limitations

- **Mapped / Built / Behavior**: All 5 observed `#115` files, 13 Locations, 15 Location FDEs, 6 core business FDEs, 7 instruction anchors, and 5 `.rodata` literals are machine-verified against the pinned binary; `src/action-wire` (`#![forbid(unsafe_code)]`, 0 external deps, clippy `-D warnings` clean) and all 11 sibling micro-crates pass offline behavioral tests.
- **Identity**: `identity` remains `false`; compiled-byte proofs are tracked separately in `research/byte-windows.json` and compiled-byte packets (no whole-component byte identity is claimed here).
- **Static-only boundary**: The captured binary was inspected statically and was never executed or emulated.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-010-node115-action-wire-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_action_wire_closure_115 -v
(cd research/work-items/RE-010-node115-action-wire-closure && sha256sum -c MANIFEST.sha256)
(cd src/action-wire && cargo test --offline && cargo clippy --offline --all-targets -- -D warnings)
```
