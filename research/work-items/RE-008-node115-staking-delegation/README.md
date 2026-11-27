# RE-008: Node #115 Staking Delegation, Undelegation, Lockup, and Governance Proposal Gates

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `staking` (`RE-008`)
- **Integrated Rust crate**: `src/node115-staking` (`src/delegation.rs`, `src/governance.rs`)
- **Static analysis only**: No captured binary execution; all bytes and relocations are read statically via ELF section offsets and disassembled with Capstone.

## Direct Binary Observations

All 7 FDE extents (9,316 bytes total), 16 instruction-aligned windows, 9 `.rodata` IEEE-754 `f64` constants, and 5 `.rela.dyn` relocation slots are verified byte-for-byte by `verify.py` against `artifacts/node/115/hl-node`:

| Function | FDE Extent | Size | Role / Verified Mechanics |
| --- | --- | --- | --- |
| `token_delegate_handler` | `0x2c68bb0..0x2c68e80` | 720 B | Checks native token exists (`[rsi+0x80] == 1` else `0x10a`), non-zero amount (`0x33`), dispatches `is_undelegate` `0 -> mode 2` (delegate), `1 -> mode 0` (undelegate; if 20-byte SIMD `user == validator`, queries registration time via slot `0x64e7e78 -> 0x3c3a0b0`, exempt set via `0x64e7e80 -> 0x46f40b0(chain)`, else enforces `min_self_delegation = [r13+0x1090]` until `reg_time + 31_557_600.0s` at `0x459058` passes), `> 1 -> mode 1` (unchecked undelegate); invokes `0x64e7e70 -> 0x3c34fd0`. |
| `c_staking_delegate_or_undelegate` | `0x3c34fd0..0x3c35a0e` | 2,622 B | Verifies validator exists in `[r13+0x10]` (`0x95`), resolves current epoch via `0x3be6f50` (`0x9b`). For `mode == 2` (delegate): unless `no_lockup & 1`, rejects disabled validator profile (`[r14+0x50] == 1`) or disabled validator state (`[r15+0x18] != 0`) with `0x10c`; computes `available = balance.saturating_sub(pending_withdrawals)` (`0x3c3588b..0x3c3588e`); calls `0x4221f40`, then `0x4225a30` on `0x1a2`. For `mode != 2` (undelegate): calls `0x4221510`, then `0x42258d0` on `0x1a2`; if 20-byte SIMD `user == validator` and remaining self-delegation is missing or `< [r13+0x308]`, sets `delegations_disabled = 1` at `[r12+0x18]`. |
| `delegate_core` | `0x4221f40..0x4222753` | 2,067 B | Rejects `available < amount` with `0x10b`; subtracts from user staking balance; indexes `.rodata 0x4578a0[chain * 8]` (`[604800.0, 120.0, 120.0, 86400.0]`) when `no_lockup == 0` to compute `locked_until = now + lockup_secs` (saturating at `Time::MAX` `0x4679d0`); adds `amount` to user delegation and validator total stake; updates per-delegator epoch-min tracker `(current, epoch_min, last_epoch)` (new entry starts with `epoch_min = 0`; existing entry on epoch rollover snapshots prior `current` into `epoch_min` before adding `amount`). |
| `undelegate_core` | `0x4221510..0x4221a8e` | 1,406 B | Rejects missing delegation or `delegated < amount` with `0x10d`; when `mode == 0`, rejects `locked_until > now` with `0x10e` and `delegated - amount < min_self_delegation` with `0x145`; subtracts from delegation (pruning empty entries) and credits user balance; subtracts from validator total stake; updates per-delegator epoch-min (`cmovb` min within same epoch, overwrite on new epoch; prunes at zero). |
| `sub_active_stake` | `0x42258d0..0x4225a2c` | 348 B | Subtracts `amount` from active validator stake `[r15+8]` (clamping to 0 with bug alert on underflow) and lowers validator epoch-min `[r15] = min([r15], new_stake)` (`cmovb`). |
| `add_active_stake` | `0x4225a30..0x4225b7f` | 335 B | Adds `amount` to active validator stake `[rbp+8]`, invoking `0x42320d0` with tag `0xc3` (`Add result error`) on `u64` overflow without wrapping. |
| `c_staking_propose_gate` | `0x3c348b0..0x3c34fca` | 1,818 B | Slot `0x64e5bd0`. Validates `1 <= title.len() <= 50` (`0x10f`), `1 <= description.len() <= 1000` (`0x110`), proposer total delegated stake `>= 1_000_000_000` (`0x3b9aca00`, `0x111`), proposal ID uniqueness (`0x112`), and existing active proposals for user `<= 2` (limit 3 per user, `0x113`). Selects voting duration from `.rodata`: `Sandbox`/`Testnet` (`300.0s` / `120.0s` at `0x455bc0..0x455bc8`), `Local`/`Mainnet` (`518400.0s` / `86400.0s` at `0x459418` / `0x459ac0`). |

### Verified `.rodata` `f64` Constants

| Anchor | VA | IEEE-754 Bits | Value (seconds) |
| --- | --- | --- | --- |
| `self_delegation_lock_1yr` | `0x459058` | `0x417e187e00000000` | `31557600.0` (365.25 days) |
| `delegation_lockup_local` | `0x4578a0` | `0x4122750000000000` | `604800.0` (7 days) |
| `delegation_lockup_sandbox` | `0x4578a8` | `0x405e000000000000` | `120.0` (2 minutes) |
| `delegation_lockup_testnet` | `0x4578b0` | `0x405e000000000000` | `120.0` (2 minutes) |
| `delegation_lockup_mainnet` | `0x4578b8` | `0x40f5180000000000` | `86400.0` (1 day) |
| `propose_duration_test_long` | `0x455bc0` | `0x4072c00000000000` | `300.0` (5 minutes) |
| `propose_duration_test_short` | `0x455bc8` | `0x405e000000000000` | `120.0` (2 minutes) |
| `propose_duration_main_long` | `0x459418` | `0x411fa40000000000` | `518400.0` (6 days) |
| `propose_duration_main_short` | `0x459ac0` | `0x40f5180000000000` | `86400.0` (1 day) |

## Inferences & Remaining Unknowns

- **Inferences**:
  - The 4-entry `f64` table at `0x4578a0` is indexed by `Chain` (`0=Local, 1=Sandbox, 2=Testnet, 3=Mainnet`), corroborated by `0x46f40b0` (`cmp dil, 3` for Mainnet) and `node115-chain-name-codec`.
  - The boolean `[rbp+0x79]` in `0x3c348b0` toggles between short and long proposal voting windows (`120s/300s` on Sandbox/Testnet; `86400s/518400s` on Local/Mainnet).
- **Unknowns (explicitly not claimed)**:
  - Unstaking/withdrawal queue scheduling and 7-day completion drain (`[state+0x268]` writers) are outside this packet and left for a subsequent slice.
  - Validator registration, commission-change (`0x132`), and full unregister (`0x3c3d480`) transitions are outside this packet.
  - The exact semantics of the global alert hook `0x64e4ea8` on defensive underflow/overflow clamping are modeled via explicit saturating arithmetic and diagnostic counters rather than runtime logging side effects.

## Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-delegation/verify.py
(cd research/work-items/RE-008-node115-staking-delegation && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_staking_delegation
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/node115-staking/Cargo.toml
```
