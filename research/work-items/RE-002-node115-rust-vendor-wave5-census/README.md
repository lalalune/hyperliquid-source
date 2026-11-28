# RE-002: node #115 Rust Vendor Wave 5 X-Ray Census (`clap` no-default-features, Nested Collections, `indexmap 2.7.1`, `tokio 1.54.1`/`h2`/`hyper`/`jsonrpsee 0.26.1`, `rocksdb`, `revm 41`)

- Component ID: `foundation` (dependency-tagged windows only; zero first-party credit)
- Target: node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `opt-level = 3`, `overflow-checks = true`, ThinLTO + `tikv-jemallocator = "=0.6.0"` (`RUSTFLAGS="-C save-temps"`), plus non-LTO `overflow-checks = true` `.rlib`s (`w5_rlib_exact`)
- Consolidation prefix: `node115-rust-vendor-w5-*`
- Claim status: observation (static parsing + unmodified crates.io / `rustc 1.95.0` sysroot builds; zero target execution)

## Summary

Guided by a `.rela.dyn` -> `.data.rel.ro` `core::panic::Location` X-ray census of uncovered node #115 `.text` FDEs (fingerprinting exact crate versions and feature sets directly against node #115 line numbers — notably discovering `clap = { version = "=2.34.0", default-features = false }`, `indexmap 2.7.1` on `hashbrown 0.15.2`, `tokio 1.54.1`/`1.52.3`, `hyper 0.14.29`, `jsonrpsee 0.26.1`, `rocksdb 0.21.0`, and `revm 41.0.0`), builds 6 locked harnesses (`w5_cli_chrono_rayon_rdb`, `w5_alloc_collections`, `w5_nested_collections_2`, `w5_http_h2_tokio_rpc`, `w5_evm_alloy_revm41`, `w5_rlib_exact`).

Admits **292 strictly disjoint, 100% relocation-qualified complete `.text` FDE windows (`+308,000 bytes`, `+0.368%` of node #115 `.text`)** across **23 crates** (`29` locked crates.io package versions, 100% permissive SPDX in `licenses.json`):

- **Highlights**:
  - **`clap 2.34.0 (default-features = false)`**: **52 FDEs = `+111,115 bytes`** (incl. single 23,327 B FDE `clap::app::validator::Validator::validate`, 9,053 B `get_required_usage_from`, 8,501 B `create_help_usage`, 7,984 B `Help::_write_parser_help`, 5,363 B `Parser::add_defaults`, 4,761 B `validate_required`).
  - **Collections & Stdlib (`alloc`, `core`, `indexmap 2.7.1`, `hashbrown 0.15.2/0.16.1`, `std`)**: **177 FDEs = `+159,376 bytes`**.
  - **HTTP/2 + Async + RPC + Storage + EVM (`tokio 1.54.1/1.52.3`, `revm-precompile 41.0.0`, `ark-ec`, `axum-core`, `hyper 0.14.29`, `h2 0.3.26`, `jsonrpsee 0.26.1`, `rocksdb 0.21.0`, `rayon-core`, `serde_json`, `itoa`, `http`, `tokio-native-tls`, `axum`, `serde_core`, `revm-interpreter`)**: **63 FDEs = `+37,509 bytes`** (incl. 14 TLS-relaxed FDEs = `7,832 B` across 19 verified `gottpoff-ie-le` psABI sites; `4` raw-equal; `0` GOTPCRELX).
- **Strict match tiers** (checked against ALL node #115 `.text` FDEs of equal length; zero `drop_in_place` glue, zero harness tokens, zero cross-crate ambiguity, zero overlap with `research/byte-windows.json` or any sibling packet):
  - `unique_fde` (`length >= 32 B`, `unmasked >= 16 B`, `rel_bytes * 2 <= length`, `hits == 1`): **165 windows = `213,972 B`** (`8` TLS-relaxed, `4` raw-equal)
  - `high_entropy_multi_copy` (`length >= 128 B`, `unmasked >= 96 B`, `rel_bytes * 2 <= length`, `2 <= hits <= 4`): **127 windows = `94,028 B`** (`6` TLS-relaxed)

### By Dependency Bucket

| Attribution | Windows | Bytes | TLS-relaxed | Raw-equal |
| --- | ---: | ---: | ---: | ---: |
| `vendored-crates` | 142 | 167,828 | 13 | 3 |
| `rust-alloc` | 107 | 103,451 | 0 | 0 |
| `rust-core` | 38 | 34,927 | 1 | 1 |
| `rust-std` | 5 | 1,794 | 0 | 0 |
| **Total** | **292** | **308,000** | **14** | **4** |

### Top Crates

| Crate | Attribution | Windows | Bytes | TLS-relaxed |
| --- | --- | ---: | ---: | ---: |
| `clap` | `vendored-crates` | 52 | 111,115 | 1 |
| `alloc` | `rust-alloc` | 107 | 103,451 | 0 |
| `core` | `rust-core` | 38 | 34,927 | 1 |
| `indexmap` | `vendored-crates` | 17 | 13,286 | 0 |
| `tokio` | `vendored-crates` | 17 | 7,052 | 12 |
| `hashbrown` | `vendored-crates` | 10 | 5,918 | 0 |
| `revm-precompile` | `vendored-crates` | 1 | 4,802 | 0 |
| `ark-ec` | `vendored-crates` | 1 | 4,207 | 0 |
| `axum-core` | `vendored-crates` | 1 | 4,016 | 0 |
| `hyper` | `vendored-crates` | 6 | 3,129 | 0 |
| `h2` | `vendored-crates` | 3 | 1,846 | 0 |
| `std` | `rust-std` | 5 | 1,794 | 0 |
| `jsonrpsee-types` | `vendored-crates` | 4 | 1,664 | 0 |
| `rocksdb` | `vendored-crates` | 4 | 1,656 | 0 |
| `rayon-core` | `vendored-crates` | 3 | 1,500 | 0 |
| Other 8 crates (`serde_json`, `itoa`, `http`, `jsonrpsee-core`, `tokio-native-tls`, `axum`, `serde_core`, `revm-interpreter`) | `vendored-crates` | 23 | 7,637 | 0 |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-rust-vendor-wave5-census/census.py --verify
(cd research/work-items/RE-002-node115-rust-vendor-wave5-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rust_vendor_wave5_census_115 -v
```
