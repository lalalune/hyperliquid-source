# RE-002: which node115 functions are unmodified crates.io dependencies?

- Component ID: foundation (dependency-tagged `vendored-crates` windows; no first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: rustc 1.95.0 (59807616e), `x86_64-unknown-linux-gnu`, cargo release
  defaults (opt-level 3, 16 codegen units, no LTO, unwind). This is the compiler named in node115's `.comment`.
- Claim status: observation (static parsing; no target execution)

## Reproduce

```sh
rustup target add x86_64-unknown-linux-gnu --toolchain 1.95.0
for b in build1 build2; do
  cp -r research/work-items/RE-002-node115-vendor-census/$b work/vendor-$b
  mkdir -p work/vendor-$b/src && : > work/vendor-$b/src/lib.rs
  (cd work/vendor-$b && cargo +1.95.0 build --locked --release \
     --target x86_64-unknown-linux-gnu --lib)
done
python3 research/work-items/RE-002-node115-vendor-census/vendor_census.py \
  work/vendor-build1/target/x86_64-unknown-linux-gnu/release/deps work/vendor-build1/Cargo.lock \
  work/vendor-build2/target/x86_64-unknown-linux-gnu/release/deps work/vendor-build2/Cargo.lock
```

- `build1` pins the crate versions named by node115's vendored directory names
  where they carry one, otherwise the version the retired historical capture embedded.
- `build2` takes the newest release of each vendored crate that `build1` did not
  match, and adds the alloy/revm family.

Both lockfiles are retained. Crates needing a Linux C/C++ sysroot (openssl,
rocksdb, blst, c-kzg, secp256k1, zstd, bzip2, keccak-asm) were left out.

## Method

The admission rule matches RE-002-node115-std-census. A function section is kept
only when all of the following hold:

- its own PC32/PLT32/GOTPCREL fields cover at most half its bytes;
- it is at least 16 bytes;
- it equals exactly one complete node115 FDE everywhere else;
- no different body claims that FDE;
- it does not overlap a registered window or a std-census body;
- its mangled symbol names the crate that produced it.

The last rule drops generic code that a crate's codegen unit instantiated for
another crate (for example `drop_in_place<Option<Waker>>` emitted in h2): those
bytes match, but they are not that crate's code.

## Results

216 windows, 88,388 bytes, across 47 crates. All are relocation-qualified and
31 are raw-equal. The largest are h2 (42 windows), chrono (33), tokio (20),
rust_decimal (12), url (10), log4rs (10), sysinfo (9) and clap (8). Crypto
leaves are also present: rand_chacha, k256, p256, blake3, curve25519-dalek-ng
and tiny-keccak. `census.json` has the per-crate summary and every record with
its crate version, symbol and relocation fields. `licenses.json` lists each
matched crate's declared license (all permissive); the compiled bodies keep
those licenses.

`revm-precompile` is a private fork in node115 (`z_forks/revm-precompile`).
Five functions from the published release are unchanged in it, so the fork's
private changes lie elsewhere.

## Limitations

- A match confirms that this crate version reproduces that body; it does not
  pin the whole crate version, feature set or the node's build profile. Eight
  records come from a lockfile that holds two versions of the crate.
- Generic code instantiated inside node crates, the eight private forks, the
  native C/C++ dependencies and crates that failed to build at the candidate
  versions are not covered.
- 82 of 131 vendored directories have no match yet. Many are generic-only
  (serde, futures, rayon, hashbrown, indexmap) and cannot match from an rlib.
- Relocation fields are masked, not resolved. No component gate claim.

Next question: which profile settings (codegen units, LTO, target-cpu) and
versions reproduce the remaining non-generic vendored code? Can a clang 22
x86_64 Linux sysroot rebuild rocksdb, zstd, blst and secp256k1?
