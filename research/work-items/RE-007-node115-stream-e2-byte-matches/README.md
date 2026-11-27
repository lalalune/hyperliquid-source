# RE-007: node #115 Stream E2 First-Party Compiled-Byte FDE Matches (219 Windows / 5,475 B across 6 Components)

- Component IDs: `vaults`, `action-wire`, `risk`, `exchange`, `dex-registry`, `l1-shared` (`RE-007` / `RE-010`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Compiler & flags: `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes --emit=obj` (`#![forbid(unsafe_code)]`, 0 external dependencies)
- Claim status: **observation** for all 219 FDE extents in `work/index/node-115-fde.tsv`, their exact `.text` SHA-256 digests, and their 100.00% relocation-qualified compiled-byte identity (0 non-relocation mismatches) against `lib.rs` compiled with `rustc 1.95.0`; **inference** for component ownership groupings across Stream E2 serde visitor types.
- Remaining unknowns: broader non-visitor business-logic FDE compiled-byte matching in `vaults`, `action-wire`, `risk`, `exchange`, `dex-registry`, and `l1-shared`.

## Summary (219 / 219 = 100.00% relocation-qualified, 0 non-relocation mismatches)

| Component | Windows | Matched `.text` Bytes | Unique Serde Visitor Types |
| --- | ---: | ---: | ---: |
| `vaults` | 42 | 1,050 B | 14 |
| `action-wire` | 60 | 1,500 B | 20 |
| `risk` | 51 | 1,275 B | 13 |
| `exchange` | 21 | 525 B | 7 |
| `dex-registry` | 36 | 900 B | 12 |
| `l1-shared` | 9 | 225 B | 3 |
| **Total** | **219** | **5,475 B** | **69** |

All 219 FDE windows are strictly disjoint from existing entries in `research/byte-windows.json` and ready for direct ingestion into `src/node115-first-party-byte-census` (bringing both `vaults` and `action-wire` from 0 B into authenticated first-party byte coverage).

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-node115-stream-e2-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e2_byte_matches_115
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-007-node115-stream-e2-byte-matches
(cd research/work-items/RE-007-node115-stream-e2-byte-matches && sha256sum -c MANIFEST.sha256)
```
