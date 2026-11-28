# RE-001: node115 First-Party Byte Census Wave 6 (Peer Logic Consolidation)

- Components: 6 first-party components (consolidated from 4 landed peer logic packets; zero dependency credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `-C opt-level=3 -C overflow-checks=yes` (plus `-C lto=thin` / `tikv-jemallocator`
  per source packet)
- Claim status: observation (static parsing + live clean-room compilation of committed peer packet sources; no target execution)

## Summary

Consolidates **82 strictly disjoint, 100% relocation-qualified first-party `.text`
FDE windows (+15,534 bytes, 4 raw-equal)** across **6 components** from 4 landed,
independently verified peer compiled-byte logic packets into
`research/byte-windows.json` (`node115-fp-w6-*`):

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `info-api` | 37 | 6,996 | 0 |
| `serialization` | 26 | 4,168 | 4 |
| `storage` | 4 | 2,218 | 0 |
| `consensus` | 11 | 1,845 | 0 |
| `staking` | 3 | 213 | 0 |
| `evm-rpc` | 1 | 94 | 0 |
| **Total** | **82** | **15,534** | **4** |

## Source Packets Consolidated (4)

- `RE-005-node115-bincode-fork-cross-cgu-identity` (26w / 4,168 B, 4 raw-equal)
- `RE-008-node115-consensus-staking-logic-byte-matches` (14w / 2,058 B)
- `RE-009-node115-db-cgu-logic-byte-matches` (4w / 2,218 B)
- `RE-015-node115-stream-f-async-and-rpc-logic-byte-matches` (38w / 7,090 B)

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave6-consolidation/consolidate.py
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave6-consolidation/consolidate.py --verify
(cd research/work-items/RE-001-node115-first-party-wave6-consolidation && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_wave6_consolidation_115 -v
```
