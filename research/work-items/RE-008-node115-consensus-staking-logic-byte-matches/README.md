# RE-008-node115-consensus-staking-logic-byte-matches

Live `rustc +1.95.0` compiled-byte verification for **14 strictly disjoint, zero-overlap, 100.00% relocation-qualified first-party `consensus` (`11` FDEs / `1,845 B`) and `staking` (`3` FDEs / `213 B`) `.text` FDEs (`2,058 B` total)** in Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

## Direct Observations (Node #115 Binary Evidence)

1. **Core `consensus` business-logic FDEs (2 FDEs / `591 B`, `logic.rs` compiled under `-C relocation-model=pie`)**:
   - `ValidatorStakes::has_quorum` (`0x4d3e1a0..0x4d3e30d`, `365 B`, `351/365` raw-equal = `96.16%`, `0` non-relocation diffs): iterates `BTreeSet<[u8; 20]>` signed validators and `L1Map<[u8; 20], u64>` total validator stakes via `#[track_caller]` `sat_sum`, then evaluates exact 128-bit `3 * signed_stake > 2 * total_stake` (`mov $3, %edx; mul %rdx; add %rcx, %rcx; cmp %rax, %rcx; sbb %rdx, %rsi; setb %al` at `+0x14e`).
   - `ValidatorStakes::contains_key` (`0x4d3e310..0x4d3e3f2`, `226 B`, `219/226` raw-equal = `96.90%`, `0` non-relocation diffs): dispatches `L1Map<[u8; 20], u64>` between `Small(VecDeque)` binary search and `Large(BTreeMap)` 20-byte `memcmp(..., 0x14)` tree search (anchored at `+0x69`).
2. **Nested `consensus` event enum & jump-table `Debug` FDEs (4 FDEs / `902 B`)**:
   - `ConsensusEvent::fmt` (`0x59d70b0..0x59d71d3`, `291 B`, `244/291` raw-equal = `83.85%`, `logic.rs` PIE): niche-packed 9-arm enum (`InMsg(MsgKind)` occupying discriminants `0..=9` via `lea -9(%rax); cmp $10; cmovae`, plus 8 `write!` unit arms `ExecutionState`, `TriggerTimeout`, `EmptyBlockTimer`, `PeriodicVoteStream`, `JailVoteTimer`, `L1Hash`, `AbciDigest`, `Artifact`).
   - `MsgKind::fmt` (`0x581fd50..0x581fe38`, `232 B`, `158/232` raw-equal = `68.10%`, `fmt_pic.rs` PIC): 10-arm jump-table `Formatter::write_str` (`ExternalTx`, `Tx`, `Block`, `Vote`, `Timeout`, `Tc`, `Heartbeat`, `HeartbeatAck`, `RpcResponse`, `RpcFailed`).
   - `ConsensusCounter::fmt` (`0x582ad40..0x582ae13`, `211 B`, `144/211` raw-equal = `68.25%`, `fmt_pic.rs` PIC): 9-arm jump-table `Formatter::write_str` (`CommittedBlocks`, `CommittedTxs`, `CommittedTxBytes`, `DroppedTxs`, `RpcRequestsRegistered`, `RpcRequestsSent`, `RoundQc`, `RoundTc`, `RoundCatchUp`).
   - `<&Block as Debug>::fmt` (`0x5941bb0..0x5941c58`, `168 B`, `133/168` raw-equal = `79.17%`, `fmt_pic.rs` PIC): `debug_struct_field4_finish` for `Block { proposer, tx_hashes, time, parent }` proving exact struct field offsets (`tx_hashes` `+0x00`, `parent` `+0x18`, `time` `+0x110`, `proposer` `+0x11c`).
3. **Custom `format_args!` newtype `Debug` FDEs for `consensus` & `staking` (8 FDEs / `565 B`, `fmt_pic.rs` PIC)**:
   - `consensus` (`5` FDEs / `352 B`): `Validator::fmt` (`0x581f7a0`, `68 B`), `<&Validator as Debug>::fmt` (`0x57d15e0`, `0x292c660`, `2 x 71 B`), `<&Broadcaster as Debug>::fmt` (`0x57d1540`, `0x241ebc0`, `2 x 71 B`).
   - `staking` (`3` FDEs / `213 B`): `<&CValidator as Debug>::fmt` (`0x53d52c0`, `0x241fce0`, `2 x 71 B`), `<&CSigner as Debug>::fmt` (`0x53d5310`, `71 B`).
4. **Disjointness & Zero-Dependency Build**:
   - Every FDE matches exact extents in `work/index/node-115-fde.tsv`, has `0` non-relocation byte differences under `tools/byte_progress.py::compare`, `#![forbid(unsafe_code)]`, `0` external crate dependencies, `0` internal overlaps, `0` overlaps with `research/byte-windows.json` (Wave-5 consolidation-safe), and `0` overlaps with all sibling compiled-byte packets.

## Inferences

- Node #115's `ValidatorStakes` stores validator stakes in `L1Map<[u8; 20], u64>` (matching the `Small(VecDeque)` / `Large(BTreeMap)` layout proved in `RE-001-node115-foundation-l1-map-byte-matches`) and computes 2/3 supermajority quorum in `u128` without overflow.
- `Validator`, `Broadcaster`, `CValidator`, and `CSigner` each copy their 20-byte `Address` wrapper onto the stack before formatting via `format_args!("<Type>({a})")`.

## Unknowns / Limits

- This packet covers 14 bounded first-party FDEs (`2,058 B`) and does not claim whole-component compiled-byte `identity: true` for `consensus` or `staking`.
- Larger allocating business-logic FDEs in `consensus` and `staking` (such as `CValidatorProfile::validate` `0x469b540` with jemalloc `sdallocx`, `CStaking::reward_rate_per_step` `0x3c38360`, and HotStuff-2 block proposal/commit handlers) remain separate follow-up slices.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-consensus-staking-logic-byte-matches/verify.py --self-test
(cd research/work-items/RE-008-node115-consensus-staking-logic-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_consensus_staking_logic_byte_matches_115 -v
```
