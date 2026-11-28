# RE-001: node115 First-Party Wave 7 Logic Consolidation

- Component IDs: 6 verified first-party components
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`
- Claim status: observation (clean-room `#![forbid(unsafe_code)]` Rust rebuilds authenticated via `tools/byte_progress.py::compare`; no target execution)

## Summary

Consolidates **34 strictly disjoint pure first-party `.text` FDE windows
(+12,095 bytes, 0 raw-equal, 0 relaxed)** across **6 components**
(`node115-fp-w7-*`) from landed Phase 7 peer first-party business-logic packets:

- `RE-004-node115-stream-e1-orderbook-assets-logic-byte-matches`: 16 windows / 4,155 B
- `RE-005-node115-transport-runtime-logic-byte-matches`: 8 windows / 6,117 B
- `RE-007-node115-risk-exchange-vaults-logic-byte-matches`: 10 windows / 1,823 B

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `node-runtime` | 3 | 3,682 | 0 |
| `transport` | 5 | 2,435 | 0 |
| `assets` | 10 | 2,157 | 0 |
| `orderbook` | 6 | 1,998 | 0 |
| `risk` | 8 | 1,476 | 0 |
| `vaults` | 2 | 347 | 0 |
| **Total** | **34** | **12,095** | **0** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave7-consolidation/consolidate.py --verify
(cd research/work-items/RE-001-node115-first-party-wave7-consolidation && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_wave7_consolidation_115 -v
```
