# RE-002: Node #115 Private-Fork (`z_forks`) ThinLTO + `tikv-jemallocator` Compiled-Byte Matches

- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Task / Component**: `RE-002` (dependency-tagged windows only: `vendored-crates`, `rust-core`, `rust-alloc`, `rust-std`; **zero first-party component credit or acceptance gates changed**).
- **Toolchain & Profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `[profile.release]` `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`.
- **Claim Status**: Observation (offline clean-room crates.io + rustc 1.95.0 sysroot rebuilds and static ELF comparison; no captured binary execution).

## Motivation

`RE-002-node115-private-forks-provenance` and `RE-002-node115-private-forks-patch-analysis` proved that node #115 links:
- `z_forks/hyper-fork` (based on `hyper 0.14.16`, alongside `z_vendor/hyper 0.14.32`),
- `z_forks/hyper-tls-fork` (based on `hyper-tls 0.5.0`, paired directly with `hyper-fork` via `HttpsConnector<HttpConnector>`),
- `z_forks/revm-precompile` (based on `revm-precompile 36.0.x`), and
- `z_forks/bincode-fork` (based on `bincode 2.0.1`).

Prior ThinLTO censuses either built `hyper 0.14.16` without `hyper-tls 0.5.0` or rejected every multi-copy function arising because node #115 links both `z_vendor/hyper 0.14.32` and `z_forks/hyper-fork 0.14.16` (plus multi-CGU `h2`/`http`/`hyper-tls` instantiations). Pairing locked offline `hyper = "=0.14.16"` + `hyper-tls = "=0.5.0"` + `h2 = "=0.3.26"/"=0.3.27"` + `tokio = "=1.44.2"/"=1.45.1"` + `revm-precompile = "=36.0.3"` + `bincode = "=2.0.1"` + `tikv-jemallocator = "=0.6.0"` across two clean-room harnesses (`zf1`, `zf2`) reproduces **284 additional strictly disjoint, 100.00% relocation-qualified `.text` FDEs (`+130,452 bytes`, `+0.156%` of `.text`)** across **13 crates** with **0 GOTPCRELX relaxations** and **0 overlaps** against `research/byte-windows.json` or any sibling work-item packet.

## Admission Tiers & Strict Attribution

All 284 windows satisfy `length >= 32 B`, `unmasked >= 16 B`, `relocation_bytes * 2 <= length`, exact complete `.eh_frame` FDE bounds, zero harness tokens (`zforks_zf`), strict defining-crate symbol extraction, permissive crates.io license verification (`licenses.json`), zero first-party credit, and zero overlap across `research/byte-windows.json` and all sibling packets:

1. **`unique_fde` (41 windows / 13,011 B)**: exact unique FDE match across all of node #115 `.text`.
2. **`zfork_location_authenticated` (22 windows / 5,786 B)**: multi-copy FDEs (`19` `hyper` + `3` `hyper-tls`) independently authenticated by node #115 `.data.rel.ro` `Location` xrefs to `z_forks/hyper-fork/` and `z_forks/hyper-tls-fork/src/client.rs:142:30` (`0x15e92e0`, `0x16e4b40`, `0x2a35030`).
3. **`high_entropy_multi_copy` (221 windows / 111,655 B)**: strictly restricted to `z_forks`-linked HTTP/TLS crates (`hyper`, `hyper-tls`, `h2`, `http`, `tokio-native-tls`, `native-tls`, `revm-precompile`, `bincode`) with `length >= 128 B`, `unmasked >= 96 B`, and `node115_hit_count <= 4`.

## Results Summary

| Dependency bucket | Windows | Bytes |
| --- | ---: | ---: |
| `vendored-crates` | 262 | 125,406 |
| `rust-core` | 20 | 4,876 |
| `rust-alloc` | 1 | 95 |
| `rust-std` | 1 | 75 |
| **Total** | **284** | **130,452** |

| Crate | Bucket | Windows | Bytes |
| --- | --- | ---: | ---: |
| `h2` | `vendored-crates` | 102 | 49,206 |
| `http` | `vendored-crates` | 63 | 42,924 |
| `hyper` | `vendored-crates` | 78 | 27,272 |
| `core` | `rust-core` | 20 | 4,876 |
| `hashbrown` | `vendored-crates` | 6 | 2,527 |
| `bytes` | `vendored-crates` | 1 | 771 |
| `tokio` | `vendored-crates` | 2 | 734 |
| `openssl` | `vendored-crates` | 1 | 638 |
| `tokio-native-tls` | `vendored-crates` | 3 | 529 |
| `hyper-tls` | `vendored-crates` | 5 | 466 |
| `pin-project-lite` | `vendored-crates` | 1 | 339 |
| `alloc` | `rust-alloc` | 1 | 95 |
| `std` | `rust-std` | 1 | 75 |

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-zforks-thinlto-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 python3 research/work-items/RE-002-node115-zforks-thinlto-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-002-node115-zforks-thinlto-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_zforks_thinlto_byte_matches_115 -v
```

## Limits

- Dependency-tagged only (`vendored-crates` / `rust-core` / `rust-alloc` / `rust-std`): awards zero first-party component credit or acceptance gates.
- Custom patched functions in `z_forks/hyper-fork/src/client/connect/http.rs` (`two matching urls`, `hyper-fork only trying ...`) remain documented in `RE-002-node115-private-forks-patch-analysis` and are not claimed as unpatched `vendored-crates`.
