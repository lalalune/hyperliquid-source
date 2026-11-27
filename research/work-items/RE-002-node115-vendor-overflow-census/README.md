# RE-002: node115 third-party Rust crate functions compiled with `-C overflow-checks=yes`

- Component ID: foundation (dependency-tagged windows only; no first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`, `x86_64-unknown-linux-gnu`,
  cargo release profile plus `RUSTFLAGS="-C overflow-checks=yes"` (opt-level 3,
  overflow-checks=yes, 16 codegen units, no LTO, unwind)
- Claim status: observation (static parsing and clean-room crates.io rebuilds; no target execution)

## Motivation

`RE-002-node115-private-forks-provenance` established that node #115 was compiled
globally with Rust integer overflow checks enabled (`overflow-checks = true`,
emitting 50,151 `overflow_panic` sites across 91 `z_vendor` crates).
`RE-002-node115-vendor-census` compiled its third-party Rust crates with default
cargo release settings (`overflow-checks = false`), matching only functions that
happened to contain no overflow-checked arithmetic (309 windows / 153,433 bytes).

Rebuilding the same locked crates.io dependency sets (plus full-feature builds
for `tokio`, `tokio-util`, `axum`, `hyper`, `bincode`, `secp256k1`, `openssl`,
`native-tls`, `log4rs`, `clap`, and `jsonrpsee-core`) with
`RUSTFLAGS="-C overflow-checks=yes"` reproduces **237 additional complete `.text`
FDEs (+183,902 bytes)** across **47 crates**, more than doubling authenticated
`vendored-crates` coverage (from 153,433 B to **337,335 B**, +119.9%).

## Reproduce

Build the six locked crates.io manifests with `rustc 1.95.0` and
`RUSTFLAGS="-C overflow-checks=yes"`:

- `research/work-items/RE-002-node115-vendor-census/build1`
- `research/work-items/RE-002-node115-vendor-census/build2`
- `research/work-items/RE-002-node115-vendor-census/gcc-revm4003`
- `research/work-items/RE-002-node115-vendor-census/gcc-forkbases`
- `research/work-items/RE-002-node115-vendor-overflow-census/extra`
- `research/work-items/RE-002-node115-vendor-overflow-census/hyper1416`

Then run `census.py` from the repository root:

```sh
SYSROOT="$(rustc +1.95.0 --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib"
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-vendor-overflow-census/census.py "$SYSROOT" \
  work/vendor-ovf-build1/target/release/deps work/vendor-ovf-build1/Cargo.lock \
  work/vendor-ovf-build2/target/release/deps work/vendor-ovf-build2/Cargo.lock \
  work/vendor-ovf-revm4003/target/x86_64-unknown-linux-gnu/release/deps work/vendor-ovf-revm4003/Cargo.lock \
  work/vendor-ovf-forkbases/target/x86_64-unknown-linux-gnu/release/deps work/vendor-ovf-forkbases/Cargo.lock \
  work/vendor-ovf-extra/target/x86_64-unknown-linux-gnu/release/deps work/vendor-ovf-extra/Cargo.lock \
  work/vendor-ovf-hyper1416/target/x86_64-unknown-linux-gnu/release/deps work/vendor-ovf-hyper1416/Cargo.lock
```

Verify the committed packet directly against `artifacts/node/115/hl-node`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-vendor-overflow-census/census.py --verify
(cd research/work-items/RE-002-node115-vendor-overflow-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_vendor_overflow_census_115 tests.test_node115_catalogue -v
```

## Method

Applies the exact adversarial-reviewed admission gates of
`RE-002-node115-vendor-census/vendor_census.py`, restricted strictly to Rust
codegen unit objects (`*.rcgu.o`; native C/C++ objects are excluded):

- length >= 32 bytes, unmasked bytes >= 16, relocation-masked bytes <= length / 2;
- body SHA-256 not present in any `rustc 1.95.0` sysroot rlib;
- relocation-masked bytes match **exactly one** complete node #115 `.text` FDE
  (no multi-copy credit for Rust bodies);
- zero cross-crate ambiguity across all six builds;
- strict own-crate mangled symbol filter (`<len><ident>` or `$LT$<ident>..`);
- zero overlap with any existing window in `research/byte-windows.json`
  (`node115-std-*`, `node115-vendor-*`, `node115-fp-*`).

## Results

**237 windows, 183,902 bytes**, 100% relocation-qualified (0 GOTPCRELX relaxations
needed), **8 raw-equal windows**, across **47 crates** (all permissive licenses
recorded in `licenses.json`):

| Top crates | Windows | Bytes | Raw-equal |
| --- | ---: | ---: | ---: |
| `k256` | 16 | 46,830 | 1 |
| `chrono` | 38 | 24,366 | 1 |
| `rust_decimal` | 24 | 15,106 | 0 |
| `curve25519-dalek-ng` | 15 | 13,544 | 1 |
| `blake3` | 11 | 7,760 | 1 |
| `httparse` | 11 | 7,178 | 1 |
| `serde_json` | 10 | 6,516 | 0 |
| `tokio` | 13 | 5,556 | 0 |
| `lz4_flex` | 4 | 4,202 | 0 |
| `h2` | 7 | 4,018 | 0 |
| `memchr` | 7 | 3,897 | 0 |
| `revm-precompile` | 5 | 3,118 | 0 |
| `sha2` | 1 | 2,998 | 0 |
| `alloy-consensus` | 4 | 2,966 | 0 |
| `idna` | 2 | 2,911 | 0 |
| `bytes` | 10 | 2,842 | 0 |
| `primitive-types` | 2 | 2,738 | 0 |
| `p256` | 4 | 2,670 | 3 |
| `aurora-engine-modexp` | 3 | 2,093 | 0 |
| `tiny-keccak` | 2 | 1,831 | 0 |
| Remaining 27 crates | 48 | 22,765 | 0 |

## Limitations

- Dependency-tagged (`vendored-crates`) only; awards zero first-party component credit.
- A match confirms `rustc 1.95.0 -C opt-level=3 -C overflow-checks=yes` reproduces
  that function body from the candidate crate version(s); it does not prove the
  whole crate version or feature matrix.
- Relocation fields are masked, not resolved.
