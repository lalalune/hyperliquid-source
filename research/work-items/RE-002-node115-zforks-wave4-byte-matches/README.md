# RE-002: Node #115 EVM/Crypto/Math/Serde Stack (`z_forks` Wave 4) ThinLTO + `tikv-jemallocator` Compiled-Byte Matches

- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Task / Component**: `RE-002` (dependency-tagged windows only: `vendored-crates`, `rust-alloc`, `rust-core`; **zero first-party component credit or acceptance gates changed**).
- **Toolchain & Profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `[profile.release]` `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`.
- **Claim Status**: Observation (offline clean-room crates.io + rustc 1.95.0 sysroot rebuilds and static ELF comparison; no captured binary execution).

## Motivation

Extending `RE-002-node115-zforks-thinlto-byte-matches` (Wave 1: `+130,452 B`), `RE-002-node115-zforks-wave2-byte-matches` (Wave 2: `+131,922 B`), and `RE-002-node115-zforks-wave3-byte-matches` (Wave 3: `+91,569 B`), Wave 4 exercises deeper EVM/crypto/math/serialization paths (`k256` ECDSA/Schnorr + `rfc6979`, `p256`, `secp256k1`, `revm-precompile` with `c-kzg`, `alloy-trie` proof verification, `alloy-sol-types`, `ruint 1.18.0`, `rust_decimal`, `ethabi`, `rmp-serde`, `rmp`, `serde_json 1.0.154`, `alloy-evm 0.39.0`) across two locked offline harnesses (`w4_evm_crypto`, `w4_math_serde_rpc`).

Even after `RE-002-node115-thinlto-wave4-census` (`+679 KB`), this reproduces **24 additional strictly disjoint, 100.00% relocation-qualified `.text` FDEs (`+19,971 bytes`)** across **11 crates** with **0 GOTPCRELX relaxations**, **10/10 permissive crates.io licenses**, and **0 overlaps** against `research/byte-windows.json` or any sibling work-item packet.

## Admission Tiers & Strict Attribution

All 24 windows satisfy `length >= 32 B`, `unmasked >= 16 B`, `relocation_bytes * 2 <= length`, exact complete `.eh_frame` FDE bounds, zero harness tokens (`zforks_w4_`), strict defining-crate symbol extraction, permissive crates.io license verification (`licenses.json`), zero first-party credit, and zero overlap across `research/byte-windows.json` and all sibling packets:

1. **`unique_fde` (15 windows / 16,307 B)**: exact unique FDE match across all of node #115 `.text`.
2. **`high_entropy_multi_copy` (9 windows / 3,664 B)**: strictly restricted to locked `vendored-crates` with `length >= 128 B`, `unmasked >= 96 B`, and `node115_hit_count <= 4`.

## Results Summary

| Dependency bucket | Windows | Bytes |
| --- | ---: | ---: |
| `vendored-crates` | 17 | 17,992 |
| `rust-alloc` | 3 | 1,238 |
| `rust-core` | 4 | 741 |
| **Total** | **24** | **19,971** |

| Crate | Bucket | Windows | Bytes |
| --- | --- | ---: | ---: |
| `rfc6979` | `vendored-crates` | 2 | 7,557 |
| `revm-precompile` | `vendored-crates` | 2 | 4,222 |
| `hashbrown` | `vendored-crates` | 4 | 2,633 |
| `alloc` | `rust-alloc` | 3 | 1,238 |
| `ethabi` | `vendored-crates` | 1 | 1,137 |
| `core` | `rust-core` | 4 | 741 |
| `serde_json` | `vendored-crates` | 1 | 708 |
| `rmp-serde` | `vendored-crates` | 2 | 484 |
| `alloy-trie` | `vendored-crates` | 2 | 436 |
| `serde_core` | `vendored-crates` | 2 | 410 |
| `rmp` | `vendored-crates` | 1 | 405 |

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-zforks-wave4-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 python3 research/work-items/RE-002-node115-zforks-wave4-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-002-node115-zforks-wave4-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_zforks_wave4_byte_matches_115 -v
```

## Limits

- Dependency-tagged only (`vendored-crates` / `rust-alloc` / `rust-core`): awards zero first-party component credit or acceptance gates.
