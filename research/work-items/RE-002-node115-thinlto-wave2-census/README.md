# RE-002: node115 ThinLTO + `tikv-jemallocator` cross-crate monomorphization & Wave 2 dependency census

- Component ID: foundation (dependency-tagged windows only; no first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `[profile.release]` `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (static parsing and clean-room crates.io + rustc 1.95.0 sysroot rebuilds; no target execution)

## Motivation

`RE-002-node115-thinlto-std-vendor-census` restricted matching strictly to
non-generic own-crate functions inside `*.<crate>-<hash>.<crate>.*.rcgu.o.rcgu.o`.
In Rust with ThinLTO, generic dependency crates (`ark-ff`, `ark-ec`, `blst`,
`primeorder`, `hashbrown`, `h2`, `http`, `tokio`, `hyper`, `serde`, `serde_core`,
`rayon-core`, `matchit`, `futures-util`, `rmp`, `core`, `alloc`, `std`) emit
their monomorphized machine code inside downstream dependency and binary CGUs.

Scanning all post-ThinLTO CGUs across four pinned clean-room harnesses (`sv1`,
`sv2`, `w2a`, `w2b` — zero first-party Hyperliquid code anywhere in the build)
under strict defining-crate symbol provenance reproduces **869 additional
complete `.text` FDEs (+583,475 bytes, +0.6969% of `.text`)** across **59 crates**,
with **30 raw-equal windows** and **0 GOTPCRELX relaxations needed**.

## Reproduce

Build the four pinned harnesses (`sv1`/`sv2` from `RE-002-node115-thinlto-std-vendor-census`
and `w2a`/`w2b` committed here) with `rustc 1.95.0` and `-C save-temps`, then run:

```sh
SYSROOT="$(rustc +1.95.0 --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib"
DEPS="work/target/thinlto-repro/x86_64-unknown-linux-gnu/release/deps"
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave2-census/census.py "$SYSROOT" \
  thinlto_sv1 "$DEPS" research/work-items/RE-002-node115-thinlto-std-vendor-census/sv1/Cargo.lock \
  thinlto_sv2 "$DEPS" research/work-items/RE-002-node115-thinlto-std-vendor-census/sv2/Cargo.lock \
  thinlto_w2a "$DEPS" research/work-items/RE-002-node115-thinlto-wave2-census/w2a/Cargo.lock \
  thinlto_w2b "$DEPS" research/work-items/RE-002-node115-thinlto-wave2-census/w2b/Cargo.lock
```

Verify the committed packet directly against `artifacts/node/115/hl-node`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave2-census/census.py --verify
(cd research/work-items/RE-002-node115-thinlto-wave2-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_thinlto_wave2_census_115 tests.test_node115_catalogue -v
```

## Method

Strict adversarial admission gates (all enforced by `census.py --verify`):

- length >= 32 bytes, unmasked bytes >= 16, relocation-masked bytes <= length / 2;
- relocation-masked bytes match **exactly one** complete node #115 `.text` FDE
  (no multi-copy credit);
- zero harness tokens (`thinlto_sv*`, `thinlto_w2*`) anywhere in the mangled symbol;
- defining crate extracted from the mangled symbol (legacy `_ZN` or v0 `_R`)
  must resolve unambiguously to either a `rustc 1.95.0` sysroot crate
  (`rust-std`, `rust-core`, `rust-alloc`, `compiler-builtins`) or a locked
  permissive crates.io package in `Cargo.lock` (`vendored-crates`, 80/80
  permissive licenses recorded in `licenses.json`);
- zero cross-crate or cross-bucket ambiguity across all four builds;
- zero overlap with any existing window in `research/byte-windows.json` or any
  sibling peer packet (`research/work-items/*/records.json`).

## Results

**869 windows, 583,475 bytes**, 100% relocation-qualified (**0 GOTPCRELX
relaxations**), **30 raw-equal windows**, across **59 crates**:

| Dependency bucket | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `vendored-crates` | 350 | 347,938 | 11 |
| `rust-core` | 285 | 120,393 | 15 |
| `rust-alloc` | 142 | 60,474 | 4 |
| `rust-std` | 92 | 54,670 | 0 |
| **Total** | **869** | **583,475** | **30** |

| Top crates | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `vendored-crates:ark-ff` | 27 | 130,230 | 5 |
| `rust-core:core` | 285 | 120,393 | 15 |
| `rust-alloc:alloc` | 142 | 60,474 | 4 |
| `rust-std:std` | 92 | 54,670 | 0 |
| `vendored-crates:ark-ec` | 10 | 43,974 | 0 |
| `vendored-crates:hashbrown` | 47 | 24,974 | 0 |
| `vendored-crates:h2` | 30 | 17,814 | 0 |
| `vendored-crates:http` | 24 | 14,523 | 1 |
| `vendored-crates:serde` | 16 | 12,821 | 0 |
| `vendored-crates:primeorder` | 5 | 12,707 | 0 |
| `vendored-crates:tokio` | 27 | 11,384 | 1 |
| `vendored-crates:blst` | 2 | 9,352 | 0 |
| `vendored-crates:hyper` | 22 | 7,541 | 0 |
| `vendored-crates:rayon-core` | 11 | 5,924 | 0 |
| `vendored-crates:serde_core` | 13 | 5,243 | 0 |
| `vendored-crates:matchit` | 2 | 3,279 | 0 |

## Limits

- Dependency-tagged only (`foundation` placeholder component with explicit
  `dependency` bucket): awards zero first-party component credit, gate credit,
  or behavioral claim.
