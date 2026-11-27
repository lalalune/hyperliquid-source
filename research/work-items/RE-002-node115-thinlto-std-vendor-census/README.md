# RE-002: node115 ThinLTO + `tikv-jemallocator` Rust stdlib and third-party crate census

- Component ID: foundation (dependency-tagged windows only; no first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  `[profile.release]` `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`,
  `#[global_allocator] tikv-jemallocator = "=0.6.0"`, `RUSTFLAGS="-C save-temps"`
- Claim status: observation (static parsing and clean-room crates.io + rustc 1.95.0 sysroot rebuilds; no target execution)

## Motivation

Earlier `RE-002` censuses built Rust dependencies as pre-LTO `.rlib`s (`lto = false`)
without linking `tikv-jemallocator` as `#[global_allocator]`. Node #115 was built
with `lto = "thin"` and `tikv-jemallocator` as its global allocator, allowing LLVM
ThinLTO to inline `_rjem_je_sdallocx(ptr, size, 0)` across crate boundaries into
both `rustc 1.95.0` sysroot crates (`std`, `core`, `alloc`, `rustc_demangle`,
`miniz_oxide`, `gimli`, `addr2line`, `object`, `adler2`) and allocating crates.io
dependencies (`sysinfo`, `url`, `log4rs`, `h2`, `chrono`, `revm-precompile`,
`hyper`, `clap`, `k256`, `aurora-engine-modexp`, `tokio`, `http`, `openssl`,
`axum`, `p256`, `serde_json`, `bytes`, `parking_lot`, `crossbeam-epoch`, etc.).

Compiling two pinned clean-room harnesses (`sv1` and `sv2`) with the exact
`lto = "thin"` + `overflow-checks = true` + `tikv-jemallocator` profile and
`-C save-temps`, then scanning ONLY post-ThinLTO codegen units originating
directly from sysroot or locked crates.io rlibs
(`*.<crate>-<hash>.<crate>.*.rcgu.o.rcgu.o`; harness CGUs excluded), reproduces
**729 additional complete `.text` FDEs (+536,016 bytes, +0.6402% of `.text`)**
across **67 crates** with **0 GOTPCRELX relaxations needed** and **11 raw-equal
windows**.

## Reproduce

Build both pinned harnesses with `rustc 1.95.0` and `-C save-temps`:

```sh
rustup target add x86_64-unknown-linux-gnu --toolchain 1.95.0
for b in sv1 sv2; do
  CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=work/target/thinlto-repro \
    RUSTFLAGS="-C save-temps" \
    cargo +1.95.0 build --locked --release --target x86_64-unknown-linux-gnu \
      --manifest-path research/work-items/RE-002-node115-thinlto-std-vendor-census/$b/Cargo.toml
done

SYSROOT="$(rustc +1.95.0 --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib"
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-std-vendor-census/census.py "$SYSROOT" \
  thinlto_sv1 work/target/thinlto-repro/x86_64-unknown-linux-gnu/release/deps research/work-items/RE-002-node115-thinlto-std-vendor-census/sv1/Cargo.lock \
  thinlto_sv2 work/target/thinlto-repro/x86_64-unknown-linux-gnu/release/deps research/work-items/RE-002-node115-thinlto-std-vendor-census/sv2/Cargo.lock
```

Verify the committed packet directly against `artifacts/node/115/hl-node`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-std-vendor-census/census.py --verify
(cd research/work-items/RE-002-node115-thinlto-std-vendor-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_thinlto_std_vendor_census_115 tests.test_node115_catalogue -v
```

## Method

Applies the exact adversarial-reviewed admission gates of
`RE-002-node115-vendor-census/vendor_census.py` and
`RE-002-node115-vendor-overflow-census/census.py`:

- post-ThinLTO sysroot and locked crates.io Rust CGUs only
  (`*.<crate>-<hash>.<crate>.*.rcgu.o.rcgu.o`; harness CGUs and native C/C++
  objects are excluded);
- length >= 32 bytes, unmasked bytes >= 16, relocation-masked bytes <= length / 2;
- relocation-masked bytes match **exactly one** complete node #115 `.text` FDE
  (no multi-copy credit);
- zero cross-crate ambiguity across both builds;
- strict own-crate mangled symbol filter (`<len><ident>` or `$LT$<ident>..`,
  supporting both legacy `_ZN` and v0 `_R` Rust mangling);
- zero overlap with any existing window in `research/byte-windows.json`
  (`node115-std-*`, `node115-vendor-*`, `node115-ovf-vendor-*`, `node115-fp-*`);
- all matched crates.io packages carry permissive licenses recorded in
  `licenses.json`.

## Results

**729 windows, 536,016 bytes**, 100% relocation-qualified (0 GOTPCRELX relaxations
needed), **11 raw-equal windows**, across **67 crates**:

| Dependency bucket | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `vendored-crates` | 442 | 320,195 | 2 |
| `rust-std` | 263 | 191,517 | 8 |
| `rust-core` | 17 | 19,103 | 1 |
| `rust-alloc` | 7 | 5,201 | 0 |
| **Total** | **729** | **536,016** | **11** |

| Top crates | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `rust-std:std` | 182 | 150,843 | 1 |
| `vendored-crates:sysinfo` | 40 | 47,726 | 0 |
| `vendored-crates:url` | 16 | 30,879 | 0 |
| `vendored-crates:log4rs` | 33 | 23,336 | 0 |
| `vendored-crates:h2` | 48 | 22,077 | 0 |
| `rust-std:rustc_demangle` | 40 | 21,618 | 3 |
| `vendored-crates:chrono` | 16 | 21,364 | 0 |
| `vendored-crates:revm-precompile` | 25 | 21,341 | 0 |
| `vendored-crates:hyper` | 53 | 20,175 | 0 |
| `vendored-crates:clap` | 34 | 19,362 | 0 |
| `rust-core:core` | 17 | 19,103 | 1 |
| `vendored-crates:k256` | 4 | 16,323 | 1 |
| `vendored-crates:aurora-engine-modexp` | 8 | 12,237 | 0 |
| `rust-std:miniz_oxide` | 7 | 9,635 | 0 |
| `vendored-crates:tokio` | 26 | 8,395 | 0 |
| `vendored-crates:http` | 12 | 6,747 | 0 |
| `vendored-crates:openssl` | 15 | 5,787 | 0 |
| `vendored-crates:axum` | 6 | 5,357 | 0 |
| `rust-alloc:alloc` | 7 | 5,201 | 0 |
| `vendored-crates:p256` | 2 | 4,971 | 0 |
| `rust-std:gimli` | 24 | 4,796 | 2 |

## Limits

- Only post-ThinLTO functions emitted out-of-line in sysroot or crates.io crate
  CGUs reachable from `sv1` and `sv2` are matched; generic instantiations inside
  harness CGUs or Hyperliquid first-party crates are excluded.
- Dependency-tagged only: awards zero first-party component credit, gate credit,
  or behavioral claim.
