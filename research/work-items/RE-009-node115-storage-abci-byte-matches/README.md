# RE-009: Node #115 First-Party `storage` & `abci` Compiled-Byte Matches

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler**: `rustc 1.95.0 (59807616e 2026-04-14)` with `--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes --emit=obj`
- **Source**: independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust in `lib.rs` (static analysis and compilation only; no captured binary execution).

## Summary

**50 authenticated first-party `.text` FDE windows · 1,903 bytes compared · 1,662/1,903 (87.34%) raw-equal bytes · 50/50 (100.00%) relocation-qualified · 0 non-relocation byte mismatches.**

| Component | Windows | Bytes | Raw-equal bytes | Relocation-qualified |
| --- | ---: | ---: | ---: | ---: |
| `storage` | 14 | 886 | 800/886 (90.29%) | 14/14 |
| `abci` | 36 | 1,017 | 862/1,017 (84.76%) | 36/36 |
| **Total** | **50** | **1,903** | **1,662/1,903 (87.34%)** | **50/50** |

## Matched Windows

- **`storage` (`IndexedArtifactContentSerde` JSON `visit_str`, 293 B × 2 = 586 B)**:
  - `0x1500470..0x1500595` (293 B, 274/293 raw, 5 rels)
  - `0x57c41a0..0x57c42c5` (293 B, 274/293 raw, 5 rels)
- **`storage` (`Visitor::expecting`, 25 B × 12 = 300 B)**:
  - `IndexedArtifactSerde` (`0x1500a40`, `0x57d19b0`), `NodeArtifact` (`0x15a0290`, `0x5616b50`), `EvmDbSerde` (`0x25eb7c0`, `0x38db780`, `0x50d93e0`), `EvmDbSerde::NoEvmDb` (`0x25eb5b0`, `0x38dbb60`, `0x50d95e0`), `DbAccountInfo` (`0x38dba40`), `FileSnapshotRequest::L4Snapshots` (`0x27731f0`).
- **`abci` (`QuorumStatus` RMP `visit_str`, 64 B × 3 = 192 B)**:
  - `0x2885db0..0x2885df0`, `0x3668e30..0x3668e70`, `0x535a8f0..0x535a930` (64 B each, 56/64 raw, 2 rels).
- **`abci` (`Visitor::expecting`, 25 B × 33 = 825 B)**:
  - `AbciStateDe` (`0x22f5c60`, `0x3c4d7b0`, `0x5616dd0`), `HashSignatureTracker` (`0x2773b90`, `0x4228f10`, `0x5b09030`), `HardforkHashTracker` (`0x27737d0`, `0x4229100`, `0x5b094d0`), `HashHardQuorum` (`0x27731b0`, `0x4229120`, `0x5b09050`), `NoopHardQuorumPolicy` (`0x2773c90`, `0x4229140`, `0x5942450`), `ColdHardQuorumPolicy` (`0x2420960`, `0x42297b0`, `0x53d63d0`), `QuorumStatus` (`0x292c9d0`, `0x36cd050`, `0x53d5d70`), `AbciDigest` (`0x292d2b0`, `0x41c6970`, `0x53d5ab0`), `VoteL1HashAction` (`0x292dd70`, `0x4454ba0`, `0x5942830`), `VoteAbciDigestAction` (`0x29b03b0`, `0x4459fd0`, `0x5941e70`), `LtHash` (`0x36cd190`), `LtHashes` (`0x38dbb80`), `ColdQuorumL1Hash` (`0x57d1970`).

## Reproducibility

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_storage_abci_byte_matches_115
```
