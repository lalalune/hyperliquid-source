# RE-002: Node #115 Dependency & Async/Network/Codec Stack (`z_forks` Wave 3) ThinLTO + `tikv-jemallocator` Compiled-Byte Matches

- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Task / Component**: `RE-002` (dependency-tagged windows only: `vendored-crates`, `rust-alloc`, `rust-core`; **zero first-party component credit or acceptance gates changed**).
- **Toolchain & Profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `[profile.release]` `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`.
- **Claim Status**: Observation (offline clean-room crates.io + rustc 1.95.0 sysroot rebuilds and static ELF comparison; no captured binary execution).

## Motivation

Extending `RE-002-node115-zforks-thinlto-byte-matches` (Wave 1: `+130,452 B`) and `RE-002-node115-zforks-wave2-byte-matches` (Wave 2: `+131,922 B`), Wave 3 builds two locked offline ThinLTO + `tikv-jemallocator` harnesses (`w3_net_async` and `w3_sys_codec`) covering the remaining async networking, WebSocket, HTTP/2, concurrency, CLI, and codec stack (`tokio`, `tokio-util`, `futures-channel`, `futures-util`, `hashbrown`, `bytes`, `hyper`, `h2`, `axum`, `matchit`, `crossbeam-deque`, `crossbeam-epoch`, `rayon-core`, `serde`, `serde_json`, `clap`, `openssl`, `tokio-native-tls`, `log4rs`, `base64`, `smallvec`, `primitive-types`, `rand`).

This reproduces **204 additional strictly disjoint, 100.00% relocation-qualified `.text` FDEs (`+91,569 bytes`, `+0.109%` of `.text`)** across **28 crates** with **0 GOTPCRELX relaxations**, **37/37 permissive crates.io licenses** (`licenses.json`), and **0 overlaps** against `research/byte-windows.json` (including Wave 5 `10.43%`) or any sibling work-item packet.

## Admission Tiers & Strict Attribution

All 204 windows satisfy `length >= 32 B`, `unmasked >= 16 B`, `relocation_bytes * 2 <= length`, exact complete `.eh_frame` FDE bounds, zero harness tokens (`zforks_w3_`), strict defining-crate symbol extraction, permissive crates.io license verification (`licenses.json`), zero first-party credit, and zero overlap across `research/byte-windows.json` and all sibling packets:

1. **`unique_fde` (22 windows / 9,349 B)**: exact unique FDE match across all of node #115 `.text`.
2. **`high_entropy_multi_copy` (182 windows / 82,220 B)**: strictly restricted to locked `vendored-crates` with `length >= 128 B`, `unmasked >= 96 B`, and `node115_hit_count <= 4`.

## Results Summary

| Dependency bucket | Windows | Bytes |
| --- | ---: | ---: |
| `vendored-crates` | 192 | 87,155 |
| `rust-alloc` | 1 | 2,378 |
| `rust-core` | 11 | 2,036 |
| **Total** | **204** | **91,569** |

| Top crates | Bucket | Windows | Bytes |
| --- | --- | ---: | ---: |
| `hashbrown` | `vendored-crates` | 30 | 17,558 |
| `tokio` | `vendored-crates` | 42 | 15,401 |
| `futures-channel` | `vendored-crates` | 19 | 11,087 |
| `bytes` | `vendored-crates` | 14 | 7,800 |
| `hyper` | `vendored-crates` | 5 | 5,189 |
| `crossbeam-deque` | `vendored-crates` | 8 | 4,198 |
| `serde` | `vendored-crates` | 15 | 4,030 |
| `futures-util` | `vendored-crates` | 8 | 2,995 |
| `h2` | `vendored-crates` | 5 | 2,945 |
| `tokio-util` | `vendored-crates` | 5 | 2,842 |
| `serde_json` | `vendored-crates` | 7 | 2,385 |
| `alloc` | `rust-alloc` | 1 | 2,378 |
| `core` | `rust-core` | 11 | 2,036 |
| `clap` | `vendored-crates` | 5 | 1,686 |
| `axum` | `vendored-crates` | 1 | 1,338 |
| `openssl` | `vendored-crates` | 5 | 1,054 |
| `matchit` | `vendored-crates` | 3 | 1,005 |
| `http` | `vendored-crates` | 2 | 944 |

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-zforks-wave3-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 python3 research/work-items/RE-002-node115-zforks-wave3-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-002-node115-zforks-wave3-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_zforks_wave3_byte_matches_115 -v
```

## Limits

- Dependency-tagged only (`vendored-crates` / `rust-alloc` / `rust-core`): awards zero first-party component credit or acceptance gates.
