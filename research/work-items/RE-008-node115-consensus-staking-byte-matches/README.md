# RE-008: Node #115 First-Party `staking` & `consensus` Compiled-Byte FDE Matches

## Target

- Binary: `artifacts/node/115/hl-node` (Linux x86-64 ELF, `105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Compiler: `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes` (`#![forbid(unsafe_code)]`, 0 external dependencies)

## Direct Observations

- Compiles `lib.rs` with `rustc +1.95.0` and compares every emitted ELF symbol against its exact `.eh_frame` FDE extent in `work/index/node-115-fde.tsv` and `artifacts/node/115/hl-node` `.text`:
  - **193 relocation-qualified first-party FDE windows (`4,825 B` total, 0 non-relocation mismatches, 0 overlaps with `research/byte-windows.json` or any peer stream byte-match packet)**:
    - **`staking`**: **162 windows / `4,050 B`** (`serde::de::Visitor::expecting` FDEs across 53 strictly `staking`/validator/delegation/governance types: `CStaking`, `CValidator`, `CSigner`, `CValidatorProfile`, `CValidatorStake`, `CValidatorStakes`, `CValidatorState`, `Delegation`, `Delegations`, `EpochDelegation`, `EpochState`, `EpochTracker`, `EpochValues`, `CWithdrawal`, `CDepositAction`, `CDepositAction2`, `CWithdrawAction`, `TokenDelegateAction`, `Staking`, `StakingLink*`, `LinkStakingUserAction`, `StakingLinkDisableTradingUserAction`, `RegisterValidatorAction`, `RetiredSigner`, `ValidatorState`, `Proposal`, `ProposalCategory`, `VoteChoice`, `Vote`, `VoteTracker`, `VoteWeight`, `GovProposeAction`, `GovVoteAction`, `VoteGlobalAction*`, `ValidatorL1VoteAction`, `ValidatorL1VoteTracker`, `L1VoteStakes`, `L1ValidatorStakes`, `ForceIncreaseEpochAction`, `ClaimRewardsAction`, `CValidatorAction*`).
    - **`consensus`**: **31 windows / `775 B`** (`serde::de::Visitor::expecting` FDEs across 12 strictly `consensus`/round/quorum/validator-config types: `Round`, `NRounds`, `Mempool`, `BuildBlockContext`, `MakeQuorumState`, `NoVoter`, `ColdHardVoter`, `HeartbeatJailingConfig`, `Validator`, `ValidatorConfig`, `ValidatorHardPolicy`, `ValidatorL1StatusAction`).
- Every window matches 100.00% of non-relocation machine-code bytes (relocation slots are strictly 4-byte x86-64 RIP-relative `disp32` fields at offset 14 recorded by the compiler's own ELF `.rela.*` section, resolving to the exact `.rodata` string literal authored in `lib.rs`).
- Every window is strictly disjoint from all 9,132 entries in `research/byte-windows.json` (which already includes Wave 3 `StakingLink`/`CValidatorAction` `visit_str` windows under `staking` and `ProposalCategory`/`VoteChoice` + 8 logic FDEs under `consensus`) as well as all peer stream byte-match packets (`RE-004`, `RE-007`, `RE-009`, `RE-012`, `RE-015`).

## Inferences

- The 3x FDE multiplicity for most `staking`/`consensus` types reflects monomorphized `serde::de::Visitor` instantiations across node #115's serialization backends (`rmp_serde` and `serde_json` across `l1` / `node` / `abci` call graphs).
- This packet expands first-party compiled-byte identity for `staking` (`+4,050 B`) and `consensus` (`+775 B`), ready for integration into `src/node115-first-party-byte-census` and `research/byte-windows.json`.

## Unknowns / Limits

- Whole-component `identity` gates for `consensus` and `staking` remain open: larger stateful routines (`try_vote`, `process_qc`, `advance_round`, `CStaking::delegate`, `CStaking::jail`, etc.) are behaviorally reconstructed and anchored in `src/node115-consensus` and `src/node115-staking` but not yet compiled to byte-identical machine code.
- No acceptance gate in `research/progress.json` is flipped by this packet.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-consensus-staking-byte-matches/verify.py --self-test
(cd research/work-items/RE-008-node115-consensus-staking-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_consensus_staking_byte_matches_115.py
```
