# RE-002: Node #115 Private-Fork Stack (`z_forks` Wave 2: `revm` / `alloy-*` / `ark-*` / RPC-codec) ThinLTO + `tikv-jemallocator` Compiled-Byte Matches

- **Target**: Linux x86-64 `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Task / Component**: `RE-002` (dependency-tagged windows only: `vendored-crates`, `rust-core`, `rust-alloc`; **zero first-party component credit or acceptance gates changed**).
- **Toolchain & Profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`, `[profile.release]` `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`.
- **Claim Status**: Observation (offline clean-room crates.io + rustc 1.95.0 sysroot rebuilds and static ELF comparison; no captured binary execution).

## Motivation

Extending `RE-002-node115-zforks-thinlto-byte-matches` (Wave 1: `+130,452 B`, `hyper 0.14.16` + `hyper-tls 0.5.0` + `h2` + `http`), Wave 2 builds two locked offline ThinLTO + `tikv-jemallocator` harnesses (`w2_revm40` and `w2_alloy_evm`) exercising the EVM/precompile/RPC dependency stack paired with node #115's `z_forks/revm-precompile` and `z_forks/reth-*` forks (`revm 40.0.3`, `alloy-evm 0.37.1`, `alloy-consensus 1.7.3`/`2.1.1`, `alloy-rpc-types-eth`, `alloy-trie`, `ark-bls12-381`, `ark-bn254`, `ark-ff`, `k256`, `secp256k1`, `serde_json`, `rmp-serde`, `rust_decimal`).

This reproduces **145 additional strictly disjoint, 100.00% relocation-qualified `.text` FDEs (`+131,922 bytes`, `+0.158%` of `.text`, including 13 100%-raw-equal FDEs)** across **20 crates** with **0 GOTPCRELX relaxations** and **0 overlaps** against `research/byte-windows.json` or any sibling work-item packet (including Wave 1 `RE-002-node115-zforks-thinlto-byte-matches` and `RE-002-node115-native-libs-wave2-census`).

## Admission Tiers & Strict Attribution

All 145 windows satisfy `length >= 32 B`, `unmasked >= 16 B`, `relocation_bytes * 2 <= length`, exact complete `.eh_frame` FDE bounds, zero harness tokens (`zforks_w2_`), strict defining-crate symbol extraction, permissive crates.io license verification (`licenses.json`), zero first-party credit, and zero overlap across `research/byte-windows.json` and all sibling packets:

1. **`unique_fde` (9 windows / 9,270 B)**: exact unique FDE match across all of node #115 `.text`.
2. **`high_entropy_multi_copy` (136 windows / 122,652 B)**: strictly restricted to locked EVM/precompile/RPC crates with `length >= 128 B`, `unmasked >= 96 B`, and `node115_hit_count <= 4`.

## Results Summary

| Dependency bucket | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `vendored-crates` | 140 | 129,999 | 13 |
| `rust-core` | 3 | 1,618 | 0 |
| `rust-alloc` | 2 | 305 | 0 |
| **Total** | **145** | **131,922** | **13** |

| Crate | Bucket | Windows | Bytes | Raw-equal |
| --- | --- | ---: | ---: | ---: |
| `ark-ff` | `vendored-crates` | 11 | 57,077 | 4 |
| `serde_json` | `vendored-crates` | 47 | 18,646 | 0 |
| `k256` | `vendored-crates` | 2 | 15,302 | 0 |
| `revm-interpreter` | `vendored-crates` | 31 | 8,664 | 9 |
| `revm-context-interface` | `vendored-crates` | 8 | 6,799 | 0 |
| `alloy-consensus` | `vendored-crates` | 12 | 5,584 | 0 |
| `revm-precompile` | `vendored-crates` | 1 | 5,181 | 0 |
| `revm-context` | `vendored-crates` | 6 | 3,528 | 0 |
| `alloy-trie` | `vendored-crates` | 4 | 1,896 | 0 |
| `core` | `rust-core` | 3 | 1,618 | 0 |
| `serde_core` | `vendored-crates` | 1 | 1,598 | 0 |
| `revm-handler` | `vendored-crates` | 4 | 1,194 | 0 |
| `secp256k1` | `vendored-crates` | 2 | 1,180 | 0 |
| `rmp-serde` | `vendored-crates` | 2 | 780 | 0 |
| `alloy-serde` | `vendored-crates` | 3 | 722 | 0 |
| `revm-state` | `vendored-crates` | 2 | 688 | 0 |
| `alloy-primitives` | `vendored-crates` | 2 | 682 | 0 |
| `alloc` | `rust-alloc` | 2 | 305 | 0 |
| `revm-bytecode` | `vendored-crates` | 1 | 293 | 0 |
| `rust_decimal` | `vendored-crates` | 1 | 185 | 0 |

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-zforks-wave2-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 CARGO_BUILD_JOBS=4 python3 research/work-items/RE-002-node115-zforks-wave2-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-002-node115-zforks-wave2-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_zforks_wave2_byte_matches_115 -v
```

## Limits

- Dependency-tagged only (`vendored-crates` / `rust-core` / `rust-alloc`): awards zero first-party component credit or acceptance gates.
