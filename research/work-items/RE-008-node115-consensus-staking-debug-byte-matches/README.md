# RE-008-node115-consensus-staking-debug-byte-matches

## Purpose

Prove **35 strictly disjoint, non-visitor, first-party ThinLTO `#[derive(Debug)]` compiled-byte `.text` FDE matches** (**10,441 B** total, **9,264 / 10,441 = 88.73% raw-byte equal**, **35/35 = 100.00% relocation-qualified**, **0 non-relocation byte differences**, **0 `Visitor::expecting` padding**) across the `consensus` (**28 FDEs / 8,384 B**) and `staking` (**7 FDEs / 2,057 B**) components of Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

## Direct Observations (Node #115 ELF & Live ThinLTO Build)

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` B, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Compiler & flags**: `rustc 1.95.0 (59807616e 2026-04-14)` with `--edition=2021 --crate-name consensus_staking_dbg -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps` on `main.rs` (`#![forbid(unsafe_code)]`, zero external dependencies).
- **FDE extent and `.rodata` string anchors**: Every one of the 35 windows matches an exact `.eh_frame` FDE `[start_va, end_va)` in `work/index/node-115-fde.tsv`, matches the live-compiled `.rcgu.o` `.text.*` body on 100.00% of non-relocation bytes, and contains RIP-relative `lea (%rip)` loads targeting the exact `.rodata` start address of every expected struct/variant/field name:

| Component | Type / Trait Impl | FDE Count | Size Each (B) | Total (B) | Target VAs |
| --- | --- | ---: | ---: | ---: | --- |
| `consensus` | `Round::fmt` | 5 | 293 | 1,465 | `0x27876b0`, `0x2e2ff10`, `0x564d0d0`, `0x5966390`, `0x5aa78c0` |
| `consensus` | `<&Round as Debug>::fmt` | 2 | 296 | 592 | `0x2d487c0`, `0x53d4fc0` |
| `consensus` | `CommittedRound::fmt` | 1 | 293 | 293 | `0x5967b80` |
| `consensus` | `<&CommittedRound as Debug>::fmt` | 1 | 296 | 296 | `0x5941440` |
| `consensus` | `BlockHash::fmt` | 3 | 293 | 879 | `0x2e336d0`, `0x59674b0`, `0x5aa9320` |
| `consensus` | `<&BlockHash as Debug>::fmt` | 2 | 296 | 592 | `0x2d48690`, `0x59408a0` |
| `consensus` | `ConsensusTxHash::fmt` | 3 | 293 | 879 | `0x2e39420`, `0x4e05de0`, `0x5aaaf60` |
| `consensus` | `<&ConsensusTxHash as Debug>::fmt` | 2 | 296 | 592 | `0x2d498f0`, `0x4d99280` |
| `consensus` | `Qc::fmt` | 1 | 456 | 456 | `0x59660c0` |
| `consensus` | `<&Qc as Debug>::fmt` | 1 | 459 | 459 | `0x59406d0` |
| `consensus` | `Tc::fmt` | 1 | 256 | 256 | `0x5966290` |
| `consensus` | `<&Cert as Debug>::fmt` | 1 | 511 | 511 | `0x5941570` |
| `consensus` | `<&CommitProof as Debug>::fmt` | 1 | 224 | 224 | `0x4f0dcb0` |
| `consensus` | `<&ClientBlock as Debug>::fmt` | 1 | 221 | 221 | `0x4f0dd90` |
| `consensus` | `<Arc<Proof> as Debug>::fmt` | 1 | 227 | 227 | `0x5aa79f0` |
| `consensus` | `Signed::fmt` | 2 | 221 | 442 | `0x4fb5970`, `0x5aaa380` |
| `staking` | `NodeIp::fmt` | 5 | 293 | 1,465 | `0x24b8a80`, `0x2afce10`, `0x2cc9a70`, `0x2e220e0`, `0x5a8b000` |
| `staking` | `<&NodeIp as Debug>::fmt` | 2 | 296 | 592 | `0x26a0fe0`, `0x5a2d200` |
| **Total** | **12 first-party types (35 FDEs)** | **35** | — | **10,441** | **9,264 raw-equal (88.73%), 0 non-reloc diffs** |

- **Disjointness**: `verify.py` confirms 0 internal overlaps, 0 overlaps with dependency windows or partial first-party windows in `research/byte-windows.json` (while permitting exact `(start, end)` first-party consolidation for Wave 4), and 0 overlaps with all sibling `research/work-items/*byte-matches*/records.json` and `*gate-closure*/records.json` packets.

## Inferences (Data-Layout Evidence Recovered from Exact Machine Code)

- `Qc` has exact in-memory size `0x68` (104 B) with fields laid out as `signatures` (`+0x00`, 32 B), `hardfork` (`+0x20`, 16 B), `round` (`+0x30`, 8 B), `certified_parent_round` (`+0x38`, 8 B), `committed_round` (`+0x40`, 8 B), and `block_hash` (`+0x48`, 32 B), while printing in source declaration order (`hardfork`, `round`, `certified_parent_round`, `committed_round`, `block_hash`, `signatures`).
- `Tc` has exact in-memory size `0x90` (144 B) with `high_qc` at `+0x00` (`0x68` B), `signatures` at `+0x68` (`0x20` B), and `round` at `+0x88` (`0x8` B).
- `Cert` is a niche-optimized 2-variant enum (`Cert::Qc(Qc)` vs `Cert::Tc { tc: Tc, higher_qc: Option<Qc> }`) whose discriminant at `+0x00` compares against `0x8000_0000_0000_0001` (`movabs + cmp`) because the 32-byte `signatures` representation consumes `0x8000_0000_0000_0000` internally and `higher_qc` sits at `+0x90`.
- `Proof` is formatted through `Arc<Proof>` at `0x5aa79f0`, placing `signed_block` (`0x178` B) at `+0x10` past the 16-byte `ArcInner` refcount header and `commit_proof` at `+0x188`.
- `Signed` places `content` (`0x130` B) at `+0x00` and `signature` at `+0x130`, printing `signature` then `content`.
- `NodeIp` is a single-variant tuple enum `NodeIp::Ip(...)` (`RE-008-node115-staking-crate-map`), matching all 7 `Ip(...)` `Debug::fmt` CGU copies.

## Unknowns / Limits

- The opaque placeholder inner types (`Opaque8`, `Opaque16`, `Opaque32Align1`, `Opaque304`, `Opaque376`, `SigMap`) in `main.rs` prove the exact outer struct/enum layouts, field offsets, niche discriminants, and `Debug::fmt` codegen of the 35 matched FDEs; they do not by themselves reconstruct the inner map/signature algorithms or non-`Debug` methods of `consensus` and `staking`.
- This packet covers 35 FDEs (`10,441 B`) and does not satisfy the full-component `identity` gate for `consensus` or `staking`.

## Verification

```bash
cd research/work-items/RE-008-node115-consensus-staking-debug-byte-matches && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-consensus-staking-debug-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_consensus_staking_debug_byte_matches_115 tests.test_consensus_staking_byte_matches_115 -v
```
