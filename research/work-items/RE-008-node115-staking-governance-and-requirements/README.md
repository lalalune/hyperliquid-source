# RE-008-node115-staking-governance-and-requirements

## Purpose

Close the remaining node #115 `staking` business-logic unknowns across `CStaking` governance voting & expired-proposal pruning, all 7 FDEs of `l1/src/exchange/stake_requirement.rs`, and the 3rd/final FDE of `l1/src/staking.rs` (`staking.rs:325`), porting all verified semantics into `src/node115-staking` (`src/governance.rs`, `src/stake_requirement.rs`, `tests/integration.rs`).

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Static analysis only**: No captured binary execution.

## Direct Observations (Node #115 ELF)

### 1. Verified FDE Inventory (11 FDEs / 10,925 B)

| Function | FDE Extent | Size (B) | Observed Semantics |
| --- | --- | ---: | --- |
| `gov_vote` | `0x3c33f10..0x3c348ae` | 2,462 | Looks up 32-byte `proposal_id` in `[state+0x130]` (`0x114` `"Proposal does not exist"`), rejects strictly when `now > proposal.end_time` (`0x117` `"Voting on the proposal has already ended."`; `now == end_time` is accepted), rejects duplicate 20-byte voter in `proposal.votes` (`0x115` `"Already voted"`), queries voter's delegated wei via `0x64e7980` (`0x116` `"Insufficient delegations to vote"` if `0`), extends voter's delegation lockup to `proposal.end_time` (`0x4221ca0`), checks `[state+0x228]` long-term lockup (clears expired lockup when `now >= lockup_end_time`; applies overflow-guarded 4x boost `if (w >> 62) == 0 { w <<= 2 }` at `0x3c343cb..0x3c343dd` when `now < lockup_end_time`), records `(weight: u64, choice: u8)`, and returns `0x1a2` (`Ok`). |
| `prune_expired_proposals` | `0x3c33520..0x3c33f07` | 2,535 | Scans `[state+0x130]` (`gov_proposals`), collects all proposals with `now >= proposal.end_time` (`0x3c336e8..0x3c33704`), removes them from `gov_proposals`, and returns the drained `Map<[u8; 32], Proposal>`. |
| `stake_requirement_iter_next` (`stake_requirement.rs:5`) | `0x294ceb0..0x294cfbe` | 270 | Iterates 4 stake categories (`0..4`), calls `0x2c58c70` for existing count, adds `1` (saturating) when `cat == target`, multiplies by `STAKE_TABLE[cat][chain]` (`0x602d1c`), and returns `0xc5` (`"Mul result error"`) on `mulq` overflow. |
| `stake_requirement_collect_{a,b,c}` (`stake_requirement.rs:5`) | `0x235a050`, `0x5b7a610`, `0x5b9c890` | 3 x 542 | Collects the 4 per-category required-stake `u64` values across all 4 categories. |
| `stake_requirement_iter_{b,c}` (`stake_requirement.rs:5`) | `0x543ef80`, `0x543ffc0` | 2 x 267 | Additional ThinLTO CGU instantiations of the `stake_requirement.rs:5` 4-category iterator. |
| `stake_requirement_count_category` (`stake_requirement.rs:64`) | `0x2c58c70..0x2c59351` | 1,761 | Dispatches on `category in 0..4` via `.rodata` jump table `0x60aeec` (`0x2c58c9f`, `0x2c58e0f`, `0x2c58cee`, `0x2c58dcd`) to count existing user deployments in each category. |
| `staking_validator_stake_rollup` (`l1/src/staking.rs:325`) | `0x3dd9480..0x3dd99d3` | 1,363 | Iterates validator-to-delegator stake maps (`0x68`-byte entries), invokes `0x4351de0`, and collects `Vec<(ValidatorKey, u64)>` (`0x28`-byte records). |
| `staking_saturating_sum_stakes` | `0x4351de0..0x4351f56` | 374 | Sums `u64` delegator stake entries (`+0x18`) using `add` + `cmovb` saturating at `u64::MAX` (`0x4351e40..0x4351e4f`). |

### 2. Verified `.rodata` 4-Category x 4-Chain Stake Requirement Table (`0x602d1c`)

| Category | Row VA | Local | Sandbox | Testnet | Mainnet |
| --- | --- | ---: | ---: | ---: | ---: |
| 0 | `0x457d00` | `100_000` | `10_000_000_000` | `10_000_000_000` | `50_000_000_000_000` |
| 1 | `0x457b00` | `50_000` | `20_000_000_000_000` | `5_000_000_000` | `20_000_000_000_000` |
| 2 | `0x457f00` | `200_000` | `50_000_000_000_000` | `10_000_000_000` | `50_000_000_000_000` |
| 3 | `0x457d00` | `100_000` | `10_000_000_000` | `10_000_000_000` | `50_000_000_000_000` |

### 3. Verified `UserError` Jump-Table (`0x7d8c1c`) Anchors

- `0xc5` -> `0x46efd79`: `"Mul result error"`
- `0x114` -> `0x46f2307`: `"Proposal does not exist"`
- `0x115` -> `0x46f27ec`: `"Already voted"`
- `0x116` -> `0x46f0dd8`: `"Insufficient delegations to vote"`
- `0x117` -> `0x46f043b`: `"Voting on the proposal has already ended."`

## Inferences & Unknowns / Limits

- **Inferences**:
  - `gov_vote` (`now > end_time` rejection) and `prune_expired_proposals` (`now >= end_time` drain) exhibit an intentional exact-boundary asymmetry at `now == end_time`: a vote arriving in the exact deadline timestamp is accepted before pruning drains the proposal.
  - Because `0x3c343cb..0x3c343dd` guards the 4x long-term vote boost with `shr $0x3e; jne skip; shl $0x2`, base weights `>= 2^62` are left unshifted rather than saturating or panicking.
- **Unknowns / Limits**:
  - The 4 category indices (`0..3`) in `stake_requirement.rs` are modeled neutrally as `Category0..Category3` because the exact Rust enum variant identifiers are not emitted as `.rodata` strings inside `0x294ceb0` or `0x2c58c70`.
  - The 3 large `l1/src/action/vote_global.rs` action-dispatch FDEs (`0x28cd7a0`, `0x538cd30`, `0x5397b50`) are mapped in `RE-008-node115-staking-crate-map` and remain outside this packet's scope.

## Verification

```bash
cd research/work-items/RE-008-node115-staking-governance-and-requirements && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-staking-governance-and-requirements/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_staking_governance_and_requirements -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/node115-staking/Cargo.toml
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --release --manifest-path src/node115-staking/Cargo.toml
CARGO_BUILD_JOBS=4 cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-staking/Cargo.toml --all-targets -- -D warnings
```
