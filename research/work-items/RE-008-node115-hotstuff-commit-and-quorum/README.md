# RE-008: Node #115 HotStuff-2 Two-Chain Commit Rule, 128-Bit 2/3 Stake Quorum & `register_block` Guards

## Target

- Binary: `artifacts/node/115/hl-node` (Linux x86-64 ELF, `105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

## Direct Observations

1. **HotStuff-2 certified two-chain commit rule (`0x2e157c0..0x2e197f5`, 16,437 B)**:
   - **Genesis zero-hash short-circuit (`0x2e15b9b..0x2e15bbd`)**: SIMD `movdqu`/`por`/`pcmpeqd`/`movmskps` checks if `B.parent_hash == [0u8; 32]`; if all zero, exits without committing.
   - **Consecutive-round two-chain check (`0x2e15d12..0x2e15d50`)**: computes `r_B = parent_cert_round(B).saturating_add(1)` (`incq; mov $-1; cmove`) and `r_P_plus_1 = parent_cert_round(P).saturating_add(2)` (`addq $2; cmovb $-1`), and requires `r_B == r_P_plus_1` (`cmpq %rdx, %rax; jne 0x2e1662a`).
   - **Monotonic commit guard (`0x2e15e38..0x2e15e59`)**: computes `r_P = parent_cert_round(P).saturating_add(1)` and checks `r_P > [state + 0x380]` (`committed_round`; `jbe 0x2e16ca9` skips stale commits).
2. **Exact 128-bit strict 2/3 stake quorum check (`0x4d3e1a0..0x4d3e30d`, 365 B, `node/src/consensus/validator_stakes.rs`)**:
   - At `0x4d3e2e4..0x4d3e305`: computes 128-bit `3 * signed_stake` (`movl $3, %edx; mulq %rdx`) and 128-bit `2 * total_stake` (`shrq $0x3f, %rsi; addq %rcx, %rcx`), then executes `cmpq %rax, %rcx; sbbq %rdx, %rsi; setb %al` — returning `true` iff `3u128 * signed_stake > 2u128 * total_stake` (strict `>`, overflow-free up to `u64::MAX`).
3. **Block-store registration guards (`0x2e1da10..0x2e1f73c`, 7,468 B, `node/src/consensus/mempool.rs`)**:
   - **Stale guard (`0x2e1da72..0x2e1da84`)**: compares `block_round` against `[mempool + 0x2c8]` (`min_stored_round`) and returns status tag `3` (`movb $0x3, %cl`) if below.
   - **Duplicate guard (`0x2e1dbee..0x2e1dbfe`)**: if `block_hash` is already present in `[mempool + 0x208]`, returns status tag `4` (`movb $0x4, %cl`, `NotNew`).
4. **Associated FDE extents verified**:
   - `0x2e1f740..0x2e1f9a5` (613 B): two-tier block/tx hash lookup helper called during commit.
   - `0x2e08b90..0x2e098d2` (3,394 B): consensus vote/message handler invoking `process_qc` (`0x2e08750`) and `on_timeout` (`0x2e112f0`).

## Inferences

- Implemented in `src/node115-consensus/src/commit.rs` (exported from `src/node115-consensus/src/lib.rs`) as pure, `#![forbid(unsafe_code)]`, zero-external-dep Rust (`has_strict_two_thirds_quorum_u128`, `block_round_from_parent_cert`, `TwoChainCommitStore`).

## Unknowns / Limits

- Full mempool eviction policy for displaced competing branches in `0x2e1da10` (`"evicting displaced block"`) and execution-state disk flush batching inside `0x2e157c0` are not completely modeled by the in-memory `TwoChainCommitStore`.
- These 5 FDEs are behaviorally reconstructed and byte-anchored, not yet compiled to byte-identical machine code; no acceptance gate in `research/progress.json` is flipped.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-hotstuff-commit-and-quorum/verify.py --self-test
(cd research/work-items/RE-008-node115-hotstuff-commit-and-quorum && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_node115_hotstuff_commit_and_quorum.py
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/consensus-staking cargo test --offline --locked --manifest-path src/node115-consensus/Cargo.toml
```
