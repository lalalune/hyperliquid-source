# RE-001: node115 First-Party `serde::Deserialize` Wave 4 Census

- Component IDs: 4 verified first-party components
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `serde_json = "=1.0.140"`,
  `rmp-serde = "=1.3.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (clean-room `#![forbid(unsafe_code)]` Rust rebuilds + exact `.rela.dyn -> .data.rel.ro -> .rodata` `&[&str]` slice-table proof; no target execution)

## Summary

Extends `RE-001-node115-first-party-serde-wave3-census` with newly mined pure
Hyperliquid compact-wire enum & struct families (every family verified inside
`l1/src/*` CGUs with exact `.rela.dyn -> .data.rel.ro -> .rodata &[&str]`
slice-table proof, including the 112-variant compact action wire enum, 18-variant
risk/margin wire enum, `Side` `['B','Bid','A','Ask']`, `TrailingStopKind`
`['Pct','Px']`/`['pct','px']`, and compact `l1/src/action` &
`l1/src/clearinghouse` wire types).

Admits **222 strictly disjoint, 100% relocation-qualified first-party `.text` FDE windows
(+48,150 bytes, 0 raw-equal, 0 relaxed)** across **4 components**
and **33 Hyperliquid families** (`node115-fp-serde4-*`), verified zero-overlap against
`research/byte-windows.json` and all sibling packets:

| Component | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `action-wire` | 107 | 25,626 | 0 |
| `risk` | 66 | 14,766 | 0 |
| `orderbook` | 43 | 7,005 | 0 |
| `exchange` | 6 | 753 | 0 |
| **Total** | **222** | **48,150** | **0** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-wave4-census/census.py --verify
(cd research/work-items/RE-001-node115-first-party-serde-wave4-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_first_party_serde_wave4_census_115 -v
```
