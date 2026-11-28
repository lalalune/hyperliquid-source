# RE-002: node #115 Rust TLS-Relaxed (`GOTTPOFF`/`TLSGD` `thread_local!`) + Runtime/CLI/Crypto/HTTP Census

- Component ID: `foundation` (dependency-tagged windows only; zero first-party credit)
- Target: node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `opt-level = 3`, `overflow-checks = true`, ThinLTO + `tikv-jemallocator = "=0.6.0"` (`RUSTFLAGS="-C save-temps"`), plus non-LTO `overflow-checks = true` `.rlib`s (`rt_rlib_tls_ovf`) and `rustc 1.95.0` sysroot `.rlib`s
- Consolidation prefix: `node115-rust-tls-rt-*`
- Claim status: observation (static parsing + unmodified crates.io / `rustc 1.95.0` sysroot builds; zero target execution)

## Summary

Uses the exact x86-64 ELF psABI TLS relaxation verifier in `tools/byte_progress.py` (`gottpoff-ie-le`, `tlsgd-gd-le`, `tlsgd-gd-ie`, landed in `e4a16a45c`) to harvest previously blocked Rust `thread_local!`-using FDEs and runtime/CLI/crypto/HTTP library functions across 6 new locked harnesses (`rt_tokio_tls_net`, `rt_http_h2_tls`, `rt_cli_regex_par_crypto`, `rt_sys_alt`, `rt_rlib_tls_ovf`, `rt_deep_thinlto`) and the 8 existing repo-locked ThinLTO builds (`sv1`, `sv2`, `w2a`, `w2b`, `w3cs`, `w3_revm41`, `w3_alloy25`, `w3_matrix`) for crates excluded by `RE-002-node115-thinlto-wave4-census` (`30c0d2d15`).

Admits **300 strictly disjoint, 100% relocation-qualified complete `.text` FDE windows (`+164,115 bytes`, `+0.196%` of node #115 `.text`)** across **26 crates** (`33` locked crates.io package versions, 100% permissive SPDX in `licenses.json`):

- **Newly unlocked Rust `thread_local!` psABI TLS-relaxed FDEs**: **121 windows = `83,344 bytes`** across **164 verified psABI TLS relaxation sites** (`160` `gottpoff-ie-le` + `4` `tlsgd-gd-le`; `0` GOTPCRELX relaxations; `3` raw-equal).
- **Strict match tiers** (verified against ALL node #115 `.text` FDEs of equal length; zero `drop_in_place` glue, zero harness tokens, zero cross-crate ambiguity, zero overlap with `research/byte-windows.json` or any sibling packet):
  - `unique_fde` (`length >= 32 B`, `unmasked >= 16 B`, `rel_bytes * 2 <= length`, `hits == 1`): **102 windows = `80,866 B`** (`65` TLS-relaxed)
  - `high_entropy_multi_copy` (`length >= 128 B`, `unmasked >= 96 B`, `rel_bytes * 2 <= length`, `2 <= hits <= 4`): **198 windows = `83,249 B`** (`56` TLS-relaxed)

### By Dependency Bucket

| Attribution | Windows | Bytes | TLS-relaxed | Raw-equal |
| --- | ---: | ---: | ---: | ---: |
| `vendored-crates` | 151 | 86,041 | 89 | 0 |
| `rust-std` | 99 | 50,264 | 28 | 2 |
| `rust-alloc` | 37 | 20,461 | 1 | 0 |
| `rust-core` | 13 | 7,349 | 3 | 1 |
| **Total** | **300** | **164,115** | **121** | **3** |

### Top Crates

| Crate | Attribution | Windows | Bytes | TLS-relaxed |
| --- | --- | ---: | ---: | ---: |
| `std` | `rust-std` | 99 | 50,264 | 28 |
| `tokio` | `vendored-crates` | 94 | 34,454 | 60 |
| `alloc` | `rust-alloc` | 37 | 20,461 | 1 |
| `log4rs` | `vendored-crates` | 5 | 10,452 | 3 |
| `core` | `rust-core` | 13 | 7,349 | 3 |
| `sysinfo` | `vendored-crates` | 2 | 6,561 | 2 |
| `rayon-core` | `vendored-crates` | 5 | 5,246 | 5 |
| `http` | `vendored-crates` | 4 | 3,772 | 4 |
| `openssl` | `vendored-crates` | 5 | 2,727 | 0 |
| `serde_json` | `vendored-crates` | 5 | 2,606 | 0 |
| `crossbeam-deque` | `vendored-crates` | 5 | 2,475 | 4 |
| `h2` | `vendored-crates` | 3 | 2,134 | 0 |
| `url` | `vendored-crates` | 1 | 2,115 | 0 |
| `blake3` | `vendored-crates` | 2 | 2,104 | 0 |
| `crossbeam-epoch` | `vendored-crates` | 4 | 2,016 | 4 |
| `parking_lot` | `vendored-crates` | 1 | 1,706 | 1 |
| Other 10 crates (`zmij`, `icu_collections`, `axum`, `arc-swap`, `tracing-core`, `rayon`, `hyper`, `once_cell`, `form_urlencoded`, `rand_core`) | `vendored-crates` | 15 | 7,773 | 6 |

## Reproduce & Verify

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-rust-tls-runtime-census/census.py --verify
(cd research/work-items/RE-002-node115-rust-tls-runtime-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rust_tls_runtime_census_115 -v
```
