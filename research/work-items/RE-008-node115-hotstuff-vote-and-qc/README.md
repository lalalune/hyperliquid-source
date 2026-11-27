# RE-008: Node #115 HotStuff Voting (`0x2e07a00`), QC Equivocation Safety (`0x2e08750` / `0x2e1fe30`), and Ancestor Chain Completeness (`0x2e20b00`)

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `consensus` (`RE-008`)
- **Integrated Rust crate**: `src/node115-consensus` (`src/voting.rs`)
- **Static analysis only**: No captured binary execution; all bytes and `.rodata` constants are read statically.

## Direct Binary Observations

| Function | FDE Extent | Size | Verified Mechanics |
| --- | --- | --- | --- |
| `try_vote` | `0x2e07a00..0x2e08745` | 3,397 B | Enforces: (1) vote pacing `now >= min_vote_time` (`0x2e07a14..0x2e07a4b`); (2) anti-double-vote `current_round > last_voted_round` (`[rbx+0xae8]`) and `current_round > committed_round` (`[rbx+0x380]`); (3) pending block for `current_round` with all `tx_hashes` present locally; (4) strictly increasing block timestamp `block.time > parent.time` (`0x2e07eeb..0x2e07f39`); (5) unbroken ancestor chain back to `committed_round` via `0x2e20b00`; (6) cumulative block tx byte cap `<= 5,000,000` B (`0x4c4b40` at `0x2e082e3`); (7) `sent_timeout == 0` (`[rbx+0x8d0]`); (8) max future timestamp drift `block.time - now <= 3.5` s (`0x459518` = `0x400c000000000000`); (9) HotStuff star routing of signed Vote to `proposer(parent_round.saturating_add(2), validator_set_round)` (`0x2e084e5`); (10) updates `last_voted_round = block_round` (`0x2e08523`) and advances `min_vote_time` by `0.05` s (`0x459038` = `0x3fa999999999999a`, 50 ms) when vote pacing is enabled. |
| `process_qc` | `0x2e08750..0x2e089f4` | 676 B | Extracts `(qc.round, qc.block_hash)`, calls `0x2e1fe30` to record and check QC equivocation, updates `state.highest_qc` (`[r15+0x720]`) when `qc.round > highest_qc.round` (`[r15+0x750]`), and invokes `advance_round(state, qc.round, None)` (`0x2e19920`). |
| `record_qc_and_check_equivocation` | `0x2e1fe30..0x2e20047` | 535 B | Checks certified-blocks map for `qc.round`; if present, compares 32-byte block hashes via SIMD `pcmpeqb` + `pmovmskb == 0xffff` (`0x2e1ff4d..0x2e1ff62`) and emits a critical safety alert on conflicting certified hashes; otherwise inserts `(qc.round, qc.block_hash)`. |
| `collect_uncommitted_ancestors` | `0x2e20b00..0x2e210ef` | 1,519 B | Walks `parent_hash` links from the candidate block down to `committed_round`, returning tag `0` (`Ok`) only when the chain lands cleanly on `committed_round` (or genesis zero hash with `committed_round == 0`), and tag `1` (`Err(missing_hash)`) if any ancestor is missing or skips past `committed_round`. |

## Inferences & Remaining Unknowns

- **Inferences**:
  - Vote pacing (`0.05` s = 50 ms at `0x459038`) caps steady-state HotStuff block rate at 20 blocks/sec when the pacing flag `[rbx+0xbd4]` is enabled.
- **Unknowns (explicitly not claimed)**:
  - Asynchronous missing-block / missing-tx fetch request scheduling (`0x2e20050`) and networking send queues remain behind value outcomes in `node115-consensus::voting`.

## Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-hotstuff-vote-and-qc/verify.py
(cd research/work-items/RE-008-node115-hotstuff-vote-and-qc && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_hotstuff_vote_and_qc -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/node115-consensus/Cargo.toml
```
