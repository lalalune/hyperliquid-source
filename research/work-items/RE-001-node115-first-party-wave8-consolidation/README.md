# RE-001: node115 First-Party Wave 8 Logic Consolidation

- Component IDs: 12 verified first-party components
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`
- Claim status: observation (clean-room `#![forbid(unsafe_code)]` Rust rebuilds authenticated via `tools/byte_progress.py::compare`; no target execution)

## Summary

Consolidates **128 strictly disjoint pure first-party `.text` FDE windows
(+45,862 bytes, 1 raw-equal, 0 relaxed)** across **12 components**
(`node115-fp-w8-*`) from 5 landed Phase 8 peer first-party business-logic packets:

- `RE-015-node115-stream-f-logic-wave2-byte-matches`: 70 windows / 29,815 B
- `RE-008-node115-consensus-bincode-encode-byte-matches`: 23 windows / 6,916 B
- `RE-010-node115-action-logic-byte-matches`: 17 windows / 3,426 B
- `RE-005-node115-transport-runtime-logic-wave2-byte-matches`: 9 windows / 3,222 B
- `RE-004-node115-stream-e1-fees-book-logic-wave2-byte-matches`: 9 windows / 2,483 B

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `info-api` | 68 | 29,739 | 0 |
| `consensus` | 23 | 6,916 | 0 |
| `l1-shared` | 7 | 2,023 | 1 |
| `node-runtime` | 4 | 1,957 | 0 |
| `action-wire` | 10 | 1,403 | 0 |
| `transport` | 5 | 1,265 | 0 |
| `assets` | 5 | 1,162 | 0 |
| `orderbook` | 2 | 958 | 0 |
| `risk` | 1 | 200 | 0 |
| `fees` | 1 | 163 | 0 |
| `bridge` | 1 | 50 | 0 |
| `evm` | 1 | 26 | 0 |
| **Total** | **128** | **45,862** | **1** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave8-consolidation/consolidate.py --verify
(cd research/work-items/RE-001-node115-first-party-wave8-consolidation && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_wave8_consolidation_115 -v
```
