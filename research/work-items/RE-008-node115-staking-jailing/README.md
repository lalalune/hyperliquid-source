# RE-008-node115-staking-jailing: validator jailing/unjailing state machine (`c_staking/jailing.rs`) and epoch snapshot quorum/profile queries (`staking.rs`)

- Component ID: `staking` (`RE-008`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `main` base `aeac8456e`; no reference source copied
- Claim status: **observation** for all FDE extents, Capstone 5.0.7 instruction rows, relocation slots, f64 constant `300.0`, and `.rodata` assertion string in `records.json`; **inference** where protocol names (e.g. `ManualUnjail`, `SelfJail`, `VoteToJail`, `weighted_median_jail_until`) are assigned; **unresolved** items listed under Results and limitations.
- Scope included and excluded:
  - Included (5 FDE-bounded functions, 10,178 bytes / 2,184 instructions total):
    1. `0x3c3c260..0x3c3cfb1` (3,409 B, `l1/src/c_staking/jailing.rs:38`) — 3-arm validator jailing/unjailing dispatch: manual unjail (`0`), self-jail (`1`), peer vote-to-jail with stake-weighted median `jail_until` (`2`).
    2. `0x3c35a10..0x3c35fdb` (1,483 B) — `jail_validator` protected-validator guard and jailed-set insertion.
    3. `0x3c35fe0..0x3c36b95` (2,997 B, `l1/src/c_staking/jailing.rs:199`) — pruning stale jail votes and expired `jailed_until` entries.
    4. `0x36c7f70..0x36c8424` (1,204 B, `l1/src/staking.rs:185`) — active-epoch validator snapshot lookup (status `0x9b` on miss) + stake projection + weight comparison via `0x422e0f0`.
    5. `0x36c7b30..0x36c7f6d` (1,085 B, `l1/src/staking.rs:239,243`) — epoch validator profile map extraction (status `0x9b` on miss, uniqueness assertion `"assertion failed: profiles.insert(validator_profile)"` at `0x79db30`).
  - Excluded: delegation/undelegation lockup writers, commission update handlers, reward distribution, native byte comparison, live execution, and whole-ELF equivalence.

## Reproduce

Run from the repository root with Python 3, Capstone 5.0.7, and Rust 1.95.0 (target ELF is read-only and never executed):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-jailing/verify.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_staking_jailing
(cd research/work-items/RE-008-node115-staking-jailing && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/consensus-staking \
  cargo test --offline --locked --manifest-path src/node115-staking/Cargo.toml
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata`, and `.rela.dyn` (type 8 = `R_X86_64_RELATIVE`). Every function start and end equals its `.eh_frame` FDE, and every selected instruction window is verified by Capstone 5.0.7 decoding from its enclosing FDE start.

### 1. Jailing action dispatch (`0x3c3c260..0x3c3cfb1`, `l1/src/c_staking/jailing.rs:38`)

Reads action tag byte `[r12]` (`0`, `1`, `2`):

- **Arm `0` (Manual Unjail, `0x3c3ca33..0x3c3cf05`)**:
  1. Searches disabled-validator store (`state+0x1e8`, B-tree or ring search `0x455a9e0`): hit returns error status **`0x99`** (`0x3c3cbf4`).
  2. Searches `jailed_validators` B-tree (`state+0x180`): miss returns **`0x1a2`** (Ok, idempotent) at `0x3c3cbd4`.
  3. Checks chain exempt set via slot `0x64e5be8` (`0x46f3fc0`): if exempt, bypasses `jailed_until` and cooldown checks and removes validator from `jailed_validators` (`0x39038f0`), returning `0x1a2`.
  4. Looks up `jailed_until[validator]` in `state+0x1a8` (B-tree `0x39006d0` or ring `0x4552ba0`, 12-byte `Time = (i32, u32, u32)` at `+0x14`): if `jail_until > now` (`setg`/`seta`/`ja` at `0x3c3cdb6..0x3c3cdd2`), returns error status **`0xa0` (160 = `JAILED_UNTIL_DISCRIMINANT`)** with the 12-byte `Time` payload (`0x3c3cea8`).
  5. Looks up `last_manual_unjail[validator]` in `state+0x1c8` (`0x3cd6600`): if present, adds **`300.0`** seconds (`0x4072c00000000000` at `.rodata` `0x458f40`, passed to slot `0x64e7e88` = `0x3d66200`); if `last_manual_unjail + 300.0s > now` (`0x3c3ce62..0x3c3ce86`), returns error status **`0x9f` (159 = `MANUAL_UNJAIL_DISCRIMINANT`)** (`0x3c3ceff`). Otherwise stores `now` (`0x3f1a470` / `0x3f19e60`), removes from `jailed_validators` (`0x39038f0`), and returns **`0x1a2`** (Ok).
- **Arm `1` (Self-Jail, `0x3c3c29a..0x3c3c2bc`)**: constructs `Option<Time>::None` and calls `0x3c35a10(state, chain, validator, None)`, returning `0x1a2`.
- **Arm `2` (Peer Vote-to-Jail, `0x3c3c2c1..0x3c3c9d3`)**:
  - Verifies target validator is active (`state+0xd0`) and not already jailed (`state+0x180`).
  - Inserts voter's vote into `state+0x98` (`0x368fa30`), gathers all votes for target (`0x3676a30`), and projects sorted `0x18`-byte `(Option<Time>, u64 weight)` entries (`0x3d6f520`).
  - **Stake-weighted median loop (`0x3c3c8b7..0x3c3c94c`)**: sums `total_stake` with saturating `u64` addition, then walks entries accumulating `cum = cum.saturating_add(weight)`:
    - If entry tag `DWORD PTR [r11] == 0` (`None`): stops without jailing (`0x3c3c90e -> 0x3c3c9ba`).
    - If `cum >= 2^63` (`test r8, r8; js`) OR `2 * cum >= total_stake` (`lea rbx, [r8+r8]; cmp rbx, rcx; jb loop`): selects `Some(entry.time)` and calls `0x3c35a10(state, chain, target, Some(entry.time))`.

### 2. Protected-validator guard & expiry (`0x3c35a10..0x3c35fdb`, `0x3c35fe0..0x3c36b95`)

- `0x3c35a10` checks chain byte `sil == 3` for the chain-3 lazy set (`0x64fdb90`), else calls slot `0x64e5be8` (`0x46f3fc0`); protected validators are guarded through slot `0x64e7f00` (`0x3c377b0`) before jailing.
- `0x3c35fe0` (`jailing.rs:199`) collects stale entries (`0x3d6e9d0` over `state+0xb0`), removes obsolete vote rows (`0x3689390` on `state+0x98`), and prunes `jailed_until` (`state+0x1a8`).

### 3. Epoch snapshot quorum & profiles (`0x36c7f70..0x36c8424`, `0x36c7b30..0x36c7f6d`, `l1/src/staking.rs`)

- Both functions look up the epoch in the ring (`0x4551810`) or B-tree snapshot store; a miss yields status **`0x9b`** (`0x36c80a3` / `0x36c7c0e`).
- `0x36c7f70` (`staking.rs:185`) projects validator weights (`0x3bcb550`) and delegates directly to `0x422e0f0` (`node115-staking-weight-comparison::exceeds_threshold`).
- `0x36c7b30` (`staking.rs:239,243`) iterates snapshot entries (`0x37c5530`), folds stakes (`0x4351de0`), and inserts into the profile map asserting uniqueness (`"assertion failed: profiles.insert(validator_profile)"` at `0x79db30`, len `0x34`).

## Implementation and comparison

Independently authored `#![forbid(unsafe_code)]` Rust reconstruction lives in [`src/node115-staking`](../../../src/node115-staking/Cargo.toml), joining all ten existing #115 staking/validator/governance micro-crates with new `jailing`, `snapshot`, and `admission` modules. Six in-memory corruption controls in `verify.py` (corrupted `300.0` f64, corrupted assertion literal, flipped `0x9f` status, flipped `0xa0` status, `jb`->`jbe` median flip, shifted `0x64e7e88` slot) are all detected.

## Results and limitations

- Verified: 5 FDEs (10,178 bytes, 2,184 Capstone 5.0.7 instructions), 10 anchored instruction windows, 15 relocation/constant/call facts, 6/6 negative controls caught.
- No component acceptance gate is requested by this packet alone (`staking` still requires binary-backed delegation/undelegation lockup accounting, commission rate transitions, and snapshot rotation writer recovery).
- Next question: locate and decode the snapshot rotation writer (who appends new epoch snapshots to the ring/B-tree store and updates `[store+0x58]`) and the delegation/undelegation lockup handler emitting error discriminants `267..270` and `306`.
