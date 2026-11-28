# RE-002: node115 ThinLTO + tikv-jemallocator Wave 3 Stdlib & Vendored-Crate Census

- Component ID: foundation (dependency-tagged windows only; zero first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (static parsing + unmodified crates.io / rustc 1.95.0 sysroot builds; no target execution)

## Summary

Extends `RE-002-node115-thinlto-wave2-census` across four locked ThinLTO +
`tikv-jemallocator` builds (`w3cs`, `w3_revm41`, `w3_alloy25`, `w3_matrix`)
exercising exact node #115 crate generations (`revm 41.0.0`/`43.0.3`,
`alloy-consensus 2.1.1`/`2.5.0`, `alloy-primitives 1.5.2`/`1.6.1`/`1.7.3`,
`alloy-trie 0.9.5`/`0.9.9`, `serde 1.0.229`, `serde_json 1.0.154`, `rmp-serde
1.3.0`/`1.3.1`, `hashbrown 0.15.2`/`0.16.1`, `indexmap 2.5.0`, `tokio 1.52.3`/`1.54.1`,
`curve25519-dalek-ng 4.1.1`, `k256 0.13.4`, `p256 0.13.2`, `blst 0.3.16`,
`jsonrpsee-core 0.26.0`/`0.26.1`, plus polymorphic `BTreeMap`/`HashMap`/`Vec::sort`
stdlib monomorphizations over standard/crates.io types).

Admits **422 strictly disjoint, 100% relocation-qualified `.text` FDE windows
(+252,257 bytes, 22 raw-equal, 0 relaxed)** across **40 crates** (`node115-w3-thinlto-*`),
all strictly attributed by defining-crate symbol provenance with zero harness tokens
and zero overlaps with `research/byte-windows.json` or any sibling peer packet:

| Attribution | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `rust-alloc` | 156 | 137,523 | 10 |
| `vendored-crates` | 198 | 94,911 | 9 |
| `rust-core` | 64 | 19,159 | 3 |
| `rust-std` | 4 | 664 | 0 |
| **Total** | **422** | **252,257** | **22** |

## Admission Gates (all enforced by `census.py --verify`)

- Complete `.text` FDE (`>= 32 B`, `>= 16 B` unmasked, masked bytes `<= 50%`);
- Exact unique node #115 `.text` FDE match via `tools/byte_progress.py::compare` (no multi-copy credit);
- Zero harness identifiers (`thinlto_sv*`, `thinlto_w2*`, `thinlto_w3*`) anywhere in symbols;
- Defining crate from `_ZN`/`_R` symbol unambiguously resolves to rustc 1.95.0 sysroot or locked permissive `Cargo.lock` package (`licenses.json` 48/48 permissive);
- Zero overlap with any other `research/byte-windows.json` window or any sibling peer packet.

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave3-census/census.py --verify
(cd research/work-items/RE-002-node115-thinlto-wave3-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_thinlto_wave3_census_115 -v
```
