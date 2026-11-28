# RE-002: node115 ThinLTO + tikv-jemallocator Wave 4 High-Entropy Multi-Copy Census

- Component ID: foundation (dependency-tagged windows only; zero first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (static parsing + unmodified crates.io / rustc 1.95.0 sysroot builds; no target execution)

## Summary

Extends `RE-002-node115-thinlto-wave3-census` across our 8 locked ThinLTO +
`tikv-jemallocator` builds (`sv1`, `sv2`, `w2a`, `w2b`, `w3cs`, `w3_revm41`,
`w3_alloy25`, `w3_matrix`) using the high-entropy ThinLTO cross-CGU duplication
tier (`length >= 128 B`, `unmasked >= 96 B`, `2 <= node115_hits <= 4`, zero
`drop_in_place` glue, zero GOTPCRELX relaxations, zero harness tokens), strictly
disjoint from the parallel Rust TLS/runtime/CLI/crypto stream (excludes
`rust-std`, `tokio*`, `tracing*`, `rayon*`, `rand*`, `parking_lot*`, `crossbeam*`,
`regex*`, `clap*`, `chrono*`, `url*`, `idna*`, `flate2*`, `openssl*`, `reqwest*`,
`rustls*`, `tungstenite*`).

Admits **1,218 strictly disjoint, 100% relocation-qualified `.text` FDE windows
(+679,264 bytes, 43 raw-equal, 0 relaxed)** across **28 crates**
(`node115-w4-thinlto-*`), verified zero-overlap against `research/byte-windows.json`
and all sibling packets:

| Attribution | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `rust-alloc` | 512 | 396,286 | 12 |
| `vendored-crates` | 410 | 170,181 | 11 |
| `rust-core` | 296 | 112,797 | 20 |
| **Total** | **1,218** | **679,264** | **43** |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave4-census/census.py --verify
(cd research/work-items/RE-002-node115-thinlto-wave4-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_thinlto_wave4_census_115 -v
```
