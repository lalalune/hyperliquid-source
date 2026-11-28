# RE-001: node115 First-Party Byte Census Wave 5 (Phase 5 Peer Consolidation)

- Components: 12 first-party components (consolidated from 7 landed Phase 5 peer packets; zero dependency credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `-C opt-level=3 -C overflow-checks=yes` (plus `-C lto=thin` / `tikv-jemallocator`
  for ThinLTO packets)
- Claim status: observation (static parsing + live clean-room compilation of committed peer packet sources; no target execution)

## Summary

Consolidates **171 strictly disjoint, 100% relocation-qualified first-party `.text`
FDE windows (+41,094 bytes, 0 raw-equal)** across **12 components** from 7 landed,
independently verified Phase 5 peer compiled-byte packets into
`research/byte-windows.json` (`node115-fp-w5-*`), lifting total authenticated
first-party `.text` coverage from **420,811 B -> 461,905 B** (**1,852 windows**
across all **23/23 components**, **0.55173%** of `.text`).

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `foundation` | 79 | 19,901 | 0 |
| `dex-registry` | 31 | 5,124 | 0 |
| `l1-shared` | 12 | 3,422 | 0 |
| `assets` | 11 | 2,974 | 0 |
| `action-wire` | 11 | 2,459 | 0 |
| `risk` | 8 | 2,050 | 0 |
| `abci` | 5 | 1,342 | 0 |
| `orderbook` | 2 | 1,272 | 0 |
| `storage` | 5 | 898 | 0 |
| `constants` | 2 | 682 | 0 |
| `exchange` | 3 | 584 | 0 |
| `vaults` | 2 | 386 | 0 |
| **Total** | **171** | **41,094** | **0** |

## Source Packets Consolidated (7)

- `RE-001-node115-foundation-l1-map-byte-matches` (79w / 19,901 B)
- `RE-004-node115-stream-e1-thinlto-logic-and-debug-byte-matches` (13w / 4,246 B)
- `RE-007-node115-stream-e2-debug-byte-matches` (36w / 8,901 B)
- `RE-007-node115-dex-registry-logic-byte-matches` (31w / 5,124 B)
- `RE-009-node115-storage-abci-jemalloc-thinlto-byte-matches` (3w / 836 B)
- `RE-009-node115-storage-abci-logic-byte-matches` (7w / 1,404 B)
- `RE-015-node115-constants-first-party-100pct-byte-matches` (2w / 682 B)

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave5-consolidation/consolidate.py
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave5-consolidation/consolidate.py --verify
(cd research/work-items/RE-001-node115-first-party-wave5-consolidation && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_wave5_consolidation_115 -v
```

## Limits

- Purely consolidates already-authenticated compiled-byte windows from landed peer
  packets into `research/byte-windows.json`; awards zero unearned gates or
  dependency credit.
