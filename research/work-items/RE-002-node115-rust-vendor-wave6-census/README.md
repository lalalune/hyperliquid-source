# RE-002: Node #115 Rust Vendored Crate & Exact-Transitive X-Ray Census (Wave 6)

## Scope & Target
- **Target artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] = tikv_jemallocator::Jemalloc`.
- **Attribution**: Strictly dependency-tagged ONLY (`vendored-crates`, `rust-alloc`, `rust-std`, `rust-core`; `component: "foundation"`, `native: false`). **Zero** first-party component credit and **zero** edits to `research/byte-windows.json`, `research/progress.json`, `src/`, or generated files.
- **Wave window prefix**: `node115-rust-vendor-w6-*`.

## X-Ray Exact-Version & Transitive-Pin Methodology
Extending Wave 5 (`RE-002-node115-rust-vendor-wave5-census`, `740b0ee65`), we parsed all 5,101 `z_vendor/` `core::panic::Location` entries via `.rela.dyn` -> `.data.rel.ro` -> `.rodata` in node #115 and scored exact line-number matches across both direct AND transitive crate dependencies:

- **`tokio = "=1.53.1"`**: **241 / 241** exact line hits against node #115's `z_vendor/tokio/` locations (vs 231/241 on `1.53.3`, 178/241 on `1.52.3`, 197/241 on `1.54.1`), paired with `features = ["full"]` (`parking_lot` enabled) and exact transitive pins:
  - `parking_lot = "=0.12.3"`, `parking_lot_core = "=0.9.10"`
  - `socket2 = "=0.6.5"`, `mio = "=1.2.4"`, `tokio-util = "=0.7.11"`
- **`h2 = "=0.3.26"`** (467/467), **`hyper = "=0.14.29"`** (189/189) & `0.14.16`, **`http = "=0.2.12"`** (81/81), **`bytes = "=1.11.1"`** (45/45) with exact transitive pins:
  - `slab = "=0.4.9"`, `httparse = "=1.9.4"`, `indexmap = "=2.7.1"`, `hashbrown = "=0.15.2"`
  - `tracing = "=0.1.41"`, `tracing-core = "=0.1.34"` (`src/callsite.rs:444`, `src/dispatcher.rs:872`)
  - `futures-core/sink/channel/util = "=0.3.31"`, `want = "=0.3.1"`
- **`log4rs = "=1.3.0"`** (`default-features = false`, matching node #115's absent `serde_yaml`/`toml`) and **`chrono = "=0.4.38"`** (`default-features = false, features = ["clock", "std", "serde"]`).
- **`rayon = "=1.10.0"`**, **`rayon-core = "=1.12.1"`**, **`crossbeam-deque = "=0.8.5"`** (5/5), **`smallvec = "=1.13.2"`** (10/10), **`itoa = "=0.4.8"`**, **`ruint = "=1.12.3"`**, **`keccak-asm = "=0.1.6"`**, **`alloy-trie = "=0.9.5"`**, **`revm = "=41.0.0"`**.

Pinning all 20 transitive crates unlocked exact byte-level matches for headline runtime functions including `tokio::runtime::builder::Builder::build` (`0x5cf9600`, `4,785 B`, 2 `gottpoff-ie-le` sites), `tokio::runtime::scheduler::multi_thread::worker::create` (`0x5ceb6d0`, `4,570 B`), `rayon_core::registry::Registry::new` (`0x15125f0`, `4,282 B`, 1 TLS site), `tokio::runtime::scheduler::multi_thread::worker::Context::run` (`0x5cecc60`, `4,274 B`), and `log4rs::FixedWindowRoller` (`0x473a740`, `3,779 B`).

## Results Summary
- **Total strictly disjoint FDEs**: **240 windows = 145,845 B** (`+0.174%` of `.text`), across **24 crates**.
- **Exact psABI TLS relaxations**: **29 windows = 21,383 B** across **32** verified sites (`31` `gottpoff-ie-le`, `1` `tlsgd-gd-le`).
- **Raw-equal windows**: **3** (`revm-interpreter`).
- **Overlap**: **0** internal overlaps, **0** overlaps against `research/byte-windows.json`, and **0** overlaps against all sibling packets.
- **License audit**: **32 / 32** locked crates in `licenses.json` verified 100% permissive SPDX (`MIT`, `MIT OR Apache-2.0`, `Apache-2.0 OR MIT`).

### Breakdown by Dependency Bucket
| Dependency Bucket | Windows | Bytes | TLS-Relaxed | Raw-Equal |
|---|---:|---:|---:|---:|
| `vendored-crates` | 193 | 122,309 | 28 | 3 |
| `rust-alloc` | 28 | 18,766 | 0 | 0 |
| `rust-std` | 10 | 2,802 | 1 | 0 |
| `rust-core` | 9 | 1,968 | 0 | 0 |
| **Total** | **240** | **145,845** | **29** | **3** |

### Breakdown by Match Tier
| Match Tier | Thresholds | Windows | Bytes | TLS-Relaxed |
|---|---|---:|---:|---:|
| `unique_fde` | `len >= 32`, `unmasked >= 16`, `rel*2 <= len`, `hits == 1` | 120 | 91,277 | 21 |
| `high_entropy_multi_copy` | `len >= 128`, `unmasked >= 96`, `rel*2 <= len`, `2 <= hits <= 4` | 120 | 54,568 | 8 |

### Breakdown by Contributing Harness (8 Locked ThinLTO Builds)
| Harness | Windows | Bytes | TLS-Relaxed |
|---|---:|---:|---:|
| `w6_h2_hyper_tokio_exact` | 88 | 61,669 | 14 |
| `w6_log4rs_chrono_hyper16` | 52 | 31,151 | 3 |
| `w6_rayon_hashbrown_indexmap_alloc` | 43 | 23,567 | 2 |
| `w6_tokio_153` | 24 | 16,972 | 7 |
| `w6_tokio_1531_deep` | 7 | 3,567 | 2 |
| `w6_http_h2_hyper_axum_deep` | 5 | 3,153 | 1 |
| `w6_chrono_ruint_keccak_itoa` | 9 | 2,944 | 0 |
| `w6_alloy_revm_deep` | 12 | 2,822 | 0 |

### Top Crates Matched
| Crate | Windows | Bytes | TLS-Relaxed |
|---|---:|---:|---:|
| `vendored-crates:tokio` | 87 | 56,521 | 19 |
| `rust-alloc:alloc` | 28 | 18,766 | 0 |
| `vendored-crates:h2` | 14 | 10,781 | 0 |
| `vendored-crates:log4rs` | 7 | 9,451 | 0 |
| `vendored-crates:hyper` | 6 | 8,975 | 1 |
| `vendored-crates:hashbrown` | 8 | 8,282 | 0 |
| `vendored-crates:rayon-core` | 13 | 8,050 | 7 |
| `vendored-crates:futures-util` | 10 | 4,069 | 0 |
| `rust-std:std` | 10 | 2,802 | 1 |
| `vendored-crates:axum` | 4 | 2,498 | 1 |
| `rust-core:core` | 9 | 1,968 | 0 |
| `vendored-crates:indexmap` | 3 | 1,936 | 0 |
| `vendored-crates:rayon` | 6 | 1,455 | 0 |
| `vendored-crates:serde_json` | 4 | 1,226 | 0 |
| `vendored-crates:tracing` | 4 | 1,216 | 0 |
| `vendored-crates:alloy-trie` | 3 | 1,197 | 0 |
| `vendored-crates:anyhow` | 8 | 1,157 | 0 |
| `vendored-crates:http` | 2 | 1,147 | 0 |
| `vendored-crates:itoa` | 3 | 1,044 | 0 |
| `vendored-crates:futures-channel` | 1 | 965 | 0 |
| `vendored-crates:revm-interpreter` | 5 | 739 | 0 |
| `vendored-crates:tokio-native-tls` | 2 | 682 | 0 |
| `vendored-crates:chrono` | 2 | 674 | 0 |
| `vendored-crates:pin-project-lite` | 1 | 244 | 0 |

## Verification
```bash
(cd research/work-items/RE-002-node115-rust-vendor-wave6-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-rust-vendor-wave6-census/census.py --verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rust_vendor_wave6_census_115 -v
```
