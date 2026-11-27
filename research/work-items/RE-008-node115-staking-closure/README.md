# RE-008: Node #115 Complete `staking` (`l1/src/staking.rs`, `l1/src/c_staking/*`, `stake_requirement.rs`, `vote_global.rs`) Full-Scope Closure

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `staking` (`l1/staking.rs`, `l1/c_staking/*` in `research/components.json`, plus closely coupled `l1/src/exchange/stake_requirement.rs` and `l1/src/action/vote_global.rs` — Stream D / `RE-008`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed staking source file (**2/2** core `l1/src/staking.rs` + `l1/src/c_staking/jailing.rs`; **4/4** extended with `l1/src/exchange/stake_requirement.rs` + `l1/src/action/vote_global.rs`), **every** `.data.rel.ro` `core::panic::Location` struct (**6/6** core, **12/12** extended), **every** `.text` FDE referencing those `Location` structs (**5/5** core, **15/15** extended = `149,255 B`), and **all 38 reconstructed `CStaking`/staking business-logic FDEs** (`59,926 B`) implemented across `src/node115-staking` and all 6 registered sibling staking crates.

## Direct Binary Observations (Exhaustive ELF Closure)

1. **Source-File & `Location` Parity (`hl-node-115.inventory.json` + `.rela.dyn`/`.data.rel.ro`/`.text`)**:
   - `l1/src/c_staking/jailing.rs` (**core**): 2/2 `Location`s (`lines 38, 199`), 2/2 FDEs (`0x3c35fe0`, `0x3c3c260`) -> `src/node115-staking/src/jailing.rs`.
   - `l1/src/staking.rs` (**core**): 4/4 `Location`s (`lines 185, 239, 243, 325`), 3/3 FDEs (`0x36c7b30`, `0x36c7f70`, `0x3dd9480`) -> `src/node115-staking/src/{snapshot,stake_requirement}.rs` + `node115-{validator-epoch-ring,staking-projection,staking-weight-comparison}`.
   - `l1/src/exchange/stake_requirement.rs` (**extended**): 4/4 `Location`s (`lines 5, 64`), 7/7 FDEs (`0x235a050`, `0x294ceb0`, `0x2c58c70`, `0x543ef80`, `0x543ffc0`, `0x5b7a610`, `0x5b9c890`) -> `src/node115-staking/src/stake_requirement.rs`.
   - `l1/src/action/vote_global.rs` (**extended**): 2/2 `Location`s (`line 1504`), 3/3 FDEs (`0x28cd7a0`, `0x538cd30`, `0x5397b50`) -> `node115-{governance-codec,governance-vote-state,vote-choice-weight}`.
2. **All 38 Reconstructed Business-Logic FDEs (`59,926 B`)**:
   - **Jailing (`jailing.rs`)**: 3-arm state machine (`0x3c3c260`), protected-validator guard (`0x3c35a10`), 300s manual unjail cooldown, stake-weighted median `jail_until`, expiry pruning (`0x3c35fe0`).
   - **Epoch Snapshots (`snapshot.rs`)**: exact epoch lookup (`0x36c8430`), quorum check (`0x36c7f70`), unique profile extraction (`0x36c7b30`), validator/signer lookup (`0x36ca5b0`).
   - **Signer Admission (`admission.rs`)**: 5-class action gate (`0x2bdb230`, `0x4d907c0`, `0x36c2030`) + 92-entry class table (`0x79dd60`).
   - **Delegation & Lockups (`delegation.rs`)**: 6 FDEs (`0x2c68bb0`, `0x3c34fd0`, `0x4221f40`, `0x4221510`, `0x42258d0`, `0x4225a30`), 4-chain lockup table (`0x4578a0`), 1-year self-delegation lock (`0x459058`), epoch-min tracking.
   - **Governance (`governance.rs`)**: proposal creation gate (`0x3c348b0`), voting with 4x overflow-guarded long-term lockup boost + delegation lockup extension (`0x3c33f10`), expired-proposal pruning (`0x3c33520`).
   - **Validator Lifecycle (`validator_lifecycle.rs`)**: registration (`0x2c77640`, `0x4225b80`), 1,000-validator cap + signer/IP cooldowns + zero-delegation unregister (`0x3c3d480`), RFC 6890 global IPv4 & commission bps validation (`0x3c3a700`, `0x469b540`).
   - **Withdrawal Queue (`withdrawal_queue.rs`)**: 3 FDEs (`0x3c3bbd0`, `0x36cb770`, `0x3c3b790`), 5-concurrent cap (`0x143`), long-term lockup guard (`0x141`), 7-day/300s delay table (`0x450d00`).
   - **Rewards & Decay (`rewards.rs`)**: 6 FDEs (`0x3c38360`, `0x3c3f780`, `0x422c320`, `0x3d66500`, `0x422abf0`, `0x422a630`), inverse-sqrt quadratic APR, 3 periodic bucket guards, reserve-capped staging, commission split, asymmetric `0.99` decay.
   - **Stake Requirements & Rollup (`stake_requirement.rs`)**: 4x4 `.rodata` stake-requirement table (`0x602d1c` -> `0x457d00`/`0x457b00`/`0x457f00`, `0x294ceb0`, `0x235a050`, `0x2c58c70`) and saturating validator stake rollup (`0x3dd9480`, `0x4351de0`).

## Complete `staking` Acceptance Inventory

- **Mapped**: 2/2 core (`l1/src/staking.rs`, `l1/src/c_staking/jailing.rs`) and 4/4 extended staking source files, 12/12 `Location`s, 15/15 Location FDEs (`149,255 B`) + 38 reconstructed business FDEs (`59,926 B`) verified against `work/index/node-115-fde.tsv`, `hl-node-115.inventory.json`, and raw ELF bytes.
- **Built & Behavior**: All 7 registered `implementation_paths` in `research/components.json` (`src/node115-staking-error-text`, `src/node115-validator-epoch-ring`, `src/node115-link-staking-state`, `src/node115-staking-projection`, `src/node115-staking-weight-comparison`, `src/node115-validator-unregister`, `src/node115-staking`) build offline, pass all 47 tests (`22` in `node115-staking` debug + `--release`, `clippy --all-targets -- -D warnings` clean, `#![forbid(unsafe_code)]`, 0 external deps), and `node115-staking` is linked into `src/hl-node`.
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`. Disjoint live-compiled `rustc 1.95.0` FDE matches currently cover **169 FDEs / 6,107 B** across `RE-008-node115-consensus-staking-byte-matches` (`162w / 4,050 B`) and `RE-008-node115-consensus-staking-debug-byte-matches` (`7w / 2,057 B`).

## Unknowns / Limits

- The 3 large `l1/src/action/vote_global.rs` dispatch FDEs (`0x28cd7a0`, `0x538cd30`, `0x5397b50`) are mapped and inventoried in full here; full global-vote execution across all exchange action variants spans `action-dispatch` and `exchange` outside `staking`'s declared `l1/staking.rs` + `l1/c_staking/*` scope.
- Compiled-byte identity covers 169 FDEs (`6,107 B`) and does not close the full-component `identity` gate.

## Verification

```bash
cd research/work-items/RE-008-node115-staking-closure && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_staking_closure_115 -v
```
