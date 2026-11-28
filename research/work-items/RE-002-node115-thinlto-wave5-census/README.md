# RE-002: node115 ThinLTO + tikv-jemallocator Wave 5 Nested-Collection & Serde/HTTP Census

- Component ID: foundation (dependency-tagged windows only; zero first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (static parsing + unmodified crates.io / rustc 1.95.0 sysroot builds; no target execution)

## Summary

Adds two locked ThinLTO + `tikv-jemallocator` harnesses (`w5_serde_http` and
`w5_btree`) targeting deep `serde_json`/`rmp-serde`/`rmp`/`bincode`/`axum`/
`serde_path_to_error`/`rust_decimal`/`alloy-primitives`/`hashbrown` code paths
and nested `BTreeMap`/`HashMap`/`IndexMap` + extended value-size
monomorphizations, strictly disjoint from the Rust TLS/runtime/CLI/crypto lane
(`#499`/`#542`).

Admits **185 strictly disjoint, 100% relocation-qualified `.text` FDE windows
(+158,351 bytes, 5 raw-equal, 0 relaxed)** across **9 crates**
(`node115-w5-thinlto-*`), verified zero-overlap against `research/byte-windows.json`
and all sibling packets (including `RE-002-node115-rust-tls-runtime-census`):

| Attribution | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `rust-alloc` | 130 | 134,006 | 5 |
| `vendored-crates` | 50 | 22,363 | 0 |
| `rust-core` | 5 | 1,982 | 0 |
| **Total** | **185** | **158,351** | **5** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave5-census/census.py --verify
(cd research/work-items/RE-002-node115-thinlto-wave5-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_thinlto_wave5_census_115 -v
```
