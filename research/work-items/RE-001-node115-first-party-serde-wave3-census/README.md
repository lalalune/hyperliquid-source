# RE-001: node115 First-Party `serde::Deserialize` Wave 3 Census

- Component IDs: 14 verified first-party components (see table below)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (clean-room `#![forbid(unsafe_code)]` Rust rebuilds + exact `.rela.dyn -> .data.rel.ro -> .rodata` `&[&str]` slice-table proof; no target execution)

## Summary

Extends `RE-001-node115-first-party-serde-thinlto-census` (Wave 1) and
`RE-001-node115-first-party-serde-wave2-census` (Wave 2) by:
1. Wrapping verified first-party Hyperliquid structs and enums inside internally-tagged
   (`#[serde(tag = "type")]`), flattened (`#[serde(flatten)]`), `serde_json::from_value`,
   and `serde_path_to_error` containers so `serde::__private::de::ContentDeserializer<serde_json::Error>`
   and sibling deserializers emit the remaining byte-identical `__FieldVisitor`
   `visit_bytes` and `visit_str` FDEs; and
2. Adding newly mined pure-Hyperliquid first-party enum/struct families and exact
   `#[serde(alias = "...")]` definitions (`OrderType`, `PerpDeployAction`,
   `SpotDeployAction`, `UserDexAbstraction`, `MarginType`, `OrderCancel`,
   `TwapCancel`, `NodeName`, etc.), strictly excluding all third-party `alloy`/`revm` types.

Admits **269 strictly disjoint, 100% relocation-qualified first-party `.text` FDE windows
(+172,294 bytes, 0 raw-equal, 0 relaxed)** across **14 components**
and **115 Hyperliquid families** (`node115-fp-serde3-*`), verified zero-overlap against
`research/byte-windows.json` and all sibling packets:

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `action-wire` | 65 | 63,783 | 0 |
| `dex-registry` | 21 | 24,616 | 0 |
| `staking` | 30 | 17,680 | 0 |
| `orderbook` | 43 | 17,642 | 0 |
| `risk` | 43 | 13,389 | 0 |
| `bridge` | 14 | 7,378 | 0 |
| `constants` | 3 | 6,570 | 0 |
| `vaults` | 16 | 6,538 | 0 |
| `assets` | 11 | 5,316 | 0 |
| `fees` | 9 | 4,384 | 0 |
| `exchange` | 4 | 1,566 | 0 |
| `evm` | 4 | 1,464 | 0 |
| `consensus` | 4 | 1,208 | 0 |
| `abci` | 2 | 760 | 0 |
| **Total** | **269** | **172,294** | **0** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-wave3-census/census.py --verify
(cd research/work-items/RE-001-node115-first-party-serde-wave3-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serde_wave3_census_115 -v
```
