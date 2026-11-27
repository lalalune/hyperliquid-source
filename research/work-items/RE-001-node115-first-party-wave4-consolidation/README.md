# RE-001: node115 First-Party Byte Census Wave 4 (Peer Compiled-Byte Consolidation)

- Components: 19 first-party components (consolidated from 14 landed Wave-4-safe peer packets; zero dependency credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `-C opt-level=3 -C overflow-checks=yes` (plus `-C lto=thin` / `tikv-jemallocator`
  for packets compiled under ThinLTO)
- Claim status: observation (static parsing + live clean-room compilation of committed peer packet sources; no target execution)

## Summary

Consolidates **511 strictly disjoint, 100% relocation-qualified first-party `.text`
FDE windows (+116,064 bytes, 1 raw-equal)** across **19 components** from 14 landed,
independently verified Phase 4 peer compiled-byte packets into
`research/byte-windows.json` (`node115-fp-w4-*`), lifting total authenticated
first-party `.text` coverage from **304,747 B -> 420,811 B** (**1,681 windows**
across all **23/23 components**, **0.50264%** of `.text`).

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `orderbook` | 66 | 27,425 | 0 |
| `constants` | 35 | 19,491 | 0 |
| `bridge` | 13 | 11,526 | 0 |
| `foundation` | 69 | 9,450 | 0 |
| `consensus` | 59 | 9,159 | 0 |
| `evm` | 8 | 8,689 | 0 |
| `serialization` | 23 | 8,514 | 1 |
| `staking` | 169 | 6,107 | 0 |
| `abci` | 19 | 5,807 | 0 |
| `exchange` | 8 | 2,545 | 0 |
| `assets` | 10 | 2,465 | 0 |
| `action-wire` | 2 | 1,174 | 0 |
| `storage` | 3 | 978 | 0 |
| `node-runtime` | 14 | 641 | 0 |
| `evm-rpc` | 2 | 618 | 0 |
| `l1-shared` | 3 | 574 | 0 |
| `fees` | 2 | 474 | 0 |
| `risk` | 3 | 352 | 0 |
| `transport` | 3 | 75 | 0 |
| **Total** | **511** | **116,064** | **1** |

## Source Packets Consolidated (14)

- `RE-001-node115-foundation-byte-matches` (69w / 9,450 B)
- `RE-005-node115-bincode-fork-cgu-100pct-identity` (1w / 209 B)
- `RE-005-node115-bincode-fork-cgu-thinlto-matches` (12w / 7,170 B)
- `RE-005-node115-bincode-fork-gate-closure` (8w / 1,044 B)
- `RE-006-node115-stream-e1-thinlto-byte-matches` (78w / 30,364 B)
- `RE-007-node115-stream-e2-logic-byte-matches` (16w / 4,645 B)
- `RE-008-node115-consensus-staking-byte-matches` (193w / 4,825 B)
- `RE-008-node115-consensus-staking-debug-byte-matches` (35w / 10,441 B)
- `RE-009-node115-storage-abci-debug-byte-matches` (22w / 6,785 B)
- `RE-011-node115-stream-f-logic-byte-matches` (23w / 20,833 B)
- `RE-012-node115-stream-c-byte-matches` (19w / 807 B non-overlapping with earlier waves)
- `RE-015-node115-constants-gate-closure` (12w / 5,031 B)
- `RE-015-node115-constants-thinlto-byte-matches` (22w / 14,354 B)
- `RE-015-node115-stream-f-byte-matches` (1w / 106 B `Chain::fmt`)

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave4-consolidation/consolidate.py
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave4-consolidation/consolidate.py --verify
(cd research/work-items/RE-001-node115-first-party-wave4-consolidation && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_wave4_consolidation_115 -v
```

## Limits

- Purely consolidates already-authenticated compiled-byte windows from landed peer
  packets into `research/byte-windows.json`; awards zero unearned gates or
  dependency credit.
- `RE-007-node115-stream-e2-debug-byte-matches` (36w / 8,901 B) is excluded from
  this wave until its `verify.py` permits exact Wave-4 consolidation in
  `research/byte-windows.json`.
