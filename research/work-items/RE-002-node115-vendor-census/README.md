# RE-002: which node115 functions are unmodified third-party dependencies?

- Component ID: foundation (dependency-tagged windows only; no first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchains, both named in node115's `.comment`:
  - rustc 1.95.0 (59807616e) for Rust crates, `x86_64-unknown-linux-gnu`,
    cargo release defaults (opt-level 3, 16 codegen units, no LTO, unwind);
  - Ubuntu 24.04 GCC `13.3.0-6ubuntu2~24.04.1` for native C/C++ `-sys` crates,
    run inside `Containerfile` (amd64). cc-rs on Ubuntu defaults to `cc`, i.e. GCC.
    The same native sources built with clang 22 matched no node115 function.
- Claim status: observation (static parsing; no target execution)

## Reproduce

Rust crates (any host):

```sh
rustup target add x86_64-unknown-linux-gnu --toolchain 1.95.0
for b in build1 build2; do
  cp -r research/work-items/RE-002-node115-vendor-census/$b work/vendor-$b
  mkdir -p work/vendor-$b/src && : > work/vendor-$b/src/lib.rs
  (cd work/vendor-$b && cargo +1.95.0 build --locked --release --target x86_64-unknown-linux-gnu --lib)
done
```

Native crates (amd64 Ubuntu 24.04 container; one build per `gcc-*` directory):

```sh
podman build --platform linux/amd64 -t hl-native-build research/work-items/RE-002-node115-vendor-census
for b in gcc-rocksdb0210 gcc-secp256k1sys0100 gcc-secp256k1sys0110 gcc-blst0316 gcc-jemalloc061 gcc-revm4003 gcc-forkbases gcc-reth-v2.3.0 gcc-reth-v2.4.1; do
  cp -r research/work-items/RE-002-node115-vendor-census/$b work/vendor-$b
  mkdir -p work/vendor-$b/src && : > work/vendor-$b/src/lib.rs
  podman run --rm --platform linux/amd64 -v "$PWD/work/vendor-$b:/w" hl-native-build \
    sh -c 'cd /w && cargo build --locked --release --lib'
done
```

Then pass every build's `deps` directory and lockfile, in this order:

```sh
python3 research/work-items/RE-002-node115-vendor-census/vendor_census.py \
  "$(rustc +1.95.0 --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib" \
  work/vendor-build1/target/x86_64-unknown-linux-gnu/release/deps work/vendor-build1/Cargo.lock \
  work/vendor-build2/target/x86_64-unknown-linux-gnu/release/deps work/vendor-build2/Cargo.lock \
  work/vendor-gcc-rocksdb0210/target/release/deps work/vendor-gcc-rocksdb0210/Cargo.lock \
  work/vendor-gcc-secp256k1sys0100/target/release/deps work/vendor-gcc-secp256k1sys0100/Cargo.lock \
  work/vendor-gcc-secp256k1sys0110/target/release/deps work/vendor-gcc-secp256k1sys0110/Cargo.lock \
  work/vendor-gcc-blst0316/target/release/deps work/vendor-gcc-blst0316/Cargo.lock \
  work/vendor-gcc-jemalloc061/target/release/deps work/vendor-gcc-jemalloc061/Cargo.lock \
  work/org-hyper-evm-sync/target/release/deps work/org-hyper-evm-sync/Cargo.lock \
  work/org-block-importer/target/release/deps work/org-block-importer/Cargo.lock \
  work/org-order_book_server/target/release/deps work/org-order_book_server/Cargo.lock \
  work/vendor-gcc-revm4003/target/release/deps work/vendor-gcc-revm4003/Cargo.lock \
  work/vendor-gcc-forkbases/target/release/deps work/vendor-gcc-forkbases/Cargo.lock \
  work/vendor-gcc-reth-v2.3.0/target/release/deps work/vendor-gcc-reth-v2.3.0/Cargo.lock \
  work/vendor-gcc-reth-v2.4.1/target/release/deps work/vendor-gcc-reth-v2.4.1/Cargo.lock
```

The `org-*` builds are the hyperliquid-dex repositories at the commits in each
`org-*/SOURCE`, built unchanged with `cargo build --release --locked` in the
same container (their lockfiles are retained here).

How the version candidates were chosen:

- `build1` pins the version in each vendored directory name where node115 records one.
  Otherwise it uses the version the retired historical capture embedded.
- `build2` takes the newest release of each vendored crate `build1` did not match,
  plus the alloy/revm family.
- The native candidates come from node115 strings:
  - `rocksdb_build_git_tag:v8.1.1` gives rocksdb 0.21.0 (librocksdb-sys 0.11.0+8.1.1,
    with its bundled zstd, lz4, snappy, zlib and bzip2);
  - `z_vendor/secp256k1-sys-0.10.0`, plus an unversioned `secp256k1-sys` directory;
  - unversioned `blst` (0.3.11 to 0.3.16 tried; 0.3.16 matches most);
  - jemalloc messages (tikv-jemalloc-sys 0.6.0 and 0.6.1 build identical code).

OpenSSL, libstdc++ and glibc are dynamic (`DT_NEEDED`), so they are not in the image.

## Method

The admission rule is the same as in RE-002-node115-std-census, with stricter
size gates for third-party code. A function section is kept only when all of
these hold:

- its own 4-byte PC-relative relocation fields (PC32, PLT32, GOTPCREL,
  GOTPCRELX) cover at most half of it;
- it is at least 32 bytes, with at least 16 unmasked bytes;
- it equals exactly one complete node115 `.text` FDE everywhere else;
- no different body claims that FDE;
- it is not byte-identical to any function in the rustc 1.95.0 sysroot rlibs
  (std ships private copies of crates such as memchr);
- it does not overlap an already registered window or a std-census body.

LLD relaxes GOTPCRELX loads of locally defined symbols, writing an opcode byte
outside the 4-byte field. A strict match is tried first. Failing that, a body
may match through the exact x86-64 psABI rewrites, defined once in
`tools/byte_progress.py` and shared with the census:

- `mov reg,[rip+GOT]` (`8b`) → `lea reg,[rip+sym]` (`8d`), at a type 41/42
  site, with the same RIP-relative ModRM and, for type 42, a REX prefix;
- `call *[rip+GOT]` (`ff 15`) → `addr32 call` (`67 e8`), at a type 41 site.

Each relaxed relocation row names its rewrite. The comparator re-checks those
bytes in both captures and counts them as relocation bytes, never as raw-equal
credit. 1,133 windows (1,561,795 bytes) need it; every
observed rewrite is `mov`→`lea`.

Rust objects (`*.rcgu.o`) are attributed to a crate only when the mangled symbol
names that crate. That includes core/alloc generics instantiated over the
crate's own types. Any other object is native, including a `-sys` crate's
static library that rustc bundles into the rlib. Native code is attributed to
the `-sys` crate whose build produced it. That includes C++ template and COMDAT
code, such as libstdc++ containers, compiled in RocksDB translation units.

`symbol` is one representative name. Registry labels say "one of N identical
bodies" when several symbols build the same body, because instantiations can
differ only through their relocation targets. `candidate_symbols` lists every name with
an identical body, and `candidate_versions` every version that builds it.

## Verification

An independent adversarial review (27 agents) re-derived 87 stratified windows
with GNU binutils and capstone, without the census code:

- target bytes, FDE extents, archive members, `.rela` entries and bodies.bin
  slices all agree;
- every differing byte sits in a recorded call/jmp rel32 or RIP-relative disp32 field.

The review also confirmed four labelling and false-positive problems, all fixed here:

- a 16-byte glibc `pthread_atfork` stub matched `blst_fr_add`, which led to the
  32/16-byte gates;
- three secp256k1 bodies are identical in 0.10.0 and 0.11.0 and now list both;
- zlib carries `version_note`, because node115 embeds ZLIB_VERSION 1.3.1 while
  the bodies match the 1.3.2 build;
- a vendored memchr body equals std's private copy and is now excluded.

Separately, the comparator now rejects a census relocation pointer that names
another window's record.

A second review (20 agents) covered the relaxation rule:

- two independent checkers re-derived 52 stratified relaxed windows (archive
  members, `.rela` types, decoded `mov`/`lea` pairs, aligned instruction streams)
  with zero unexplained bytes;
- a semantic check found no misattribution across all 2,981 relaxed sites.

Its confirmed findings are fixed here:

- shape checks: RIP-relative ModRM, REX for type 42, and the call form only on
  type 41;
- the census and comparator share one rule, and overlapping rewrite bytes are rejected;
- multi-candidate labels no longer present one symbol as authoritative.

## hyperliquid-dex repository sweep

All 11 public hyperliquid-dex repositories were checked for build inputs that
pin node dependencies. The six pinned upstream submodules are at their latest
commits.

| Repository | Use here |
| --- | --- |
| `node` | `Dockerfile` is `FROM ubuntu:24.04`, consistent with the Ubuntu GCC 13.3 toolchain in node115's `.comment` |
| `block-importer` | Imports data into hl-node; its lock pins `rocksdb 0.21.0`, independently confirming `rocksdb_build_git_tag:v8.1.1`; also reth v1.3.0 and revm 20-alpha |
| `hyper-evm-sync` | Lock pins alloy 0.9.2, revm 19.2.0, reth v1.1.5, hyper 0.14.32 (the base of node115's private `hyper-fork`) and the zlib 1.3.1 era of libz-sys |
| `order_book_server` | Lock pins alloy 1.0.23, secp256k1 0.30.0 / secp256k1-sys 0.10.1 |
| `hyperliquid-rust-sdk`, `hyperliquid-python-sdk`, `ts-examples`, `contracts`, `hyperliquid-stats(-web)`, `historical_data` | No lockfile or no native-node dependency information |

Building the three Rust repositories exactly as locked supplies internally
consistent dependency generations that a free-standing resolver could not build.
A sweep of revm 24.0.1 to 42.0.1 found the node's revm family closest to
revm 40.0.0–41.0.0 (revm-precompile 36.x): 13.9 KB match there, versus 0.6 KB
at revm 24–36 and 10.5 KB at 42.0.1. The org builds also exposed identical machine
code in different crates (hyper vs aws-smithy, bytes vs rustls, a RocksDB method
vs aws-lc-sys). Those 6 previously credited windows are now dropped as ambiguous.

## Results

6,665 windows, 4,886,344 bytes, all relocation-qualified, 433 raw-equal:

| Attribution | Windows | Bytes |
| --- | ---: | ---: |
| native-libraries (GCC 13.3) | 6,359 | 4,734,012 |
| vendored-crates (rustc 1.95.0) | 306 | 152,332 |

| Native library | Windows | Bytes |
| --- | ---: | ---: |
| librocksdb-sys | 5,605 | 3,884,378 |
| zstd-sys | 310 | 518,054 |
| tikv-jemalloc-sys | 243 | 108,853 |
| blst | 118 | 68,697 |
| bzip2-sys | 18 | 67,607 |
| libz-sys | 32 | 47,183 |
| secp256k1-sys | 25 | 38,866 |
| lz4-sys | 8 | 374 |

The largest Rust contributors are h2, sha2, http, revm-precompile, tokio, rand_chacha, chrono, url, ripemd, k256. Of the eight private forks:

- `revm-precompile` matches 12.8 KB of revm-precompile 36.x;
- `hyper-fork` matches hyper 0.14.32 in its unmodified functions;
- `bincode-fork` and `hyper-tls-fork` (bases bincode 1.3.3 and hyper-tls 0.5.0)
  expose no unique non-generic body;
- the four reth crates (one or two source files each) are git-only. reth v2.3.0
  pins exactly revm 40.0.3, the revm peak above, and v2.4.1 pins revm 41.0.0.
  Building the four fork bases at both tags matches no unique non-generic body of
  those crates; the forked files are modified or generic. These builds add
  alloy-evm and alloy 2.x code.

`census.json` has the per-crate summary and every record. `licenses.json` gives
each matched crate version's declared license (all permissive); the compiled
bodies keep those licenses.

## Limitations

- A match confirms that this build reproduces that body. It does not pin a whole
  crate version, feature set or link order, and it is not a whole-library rebuild.
  Unmatched functions may differ by version, flags, inlining or duplication.
- Generic Rust code instantiated inside node crates and the eight private forks
  are not covered. Rust crates that failed to build at the candidate versions are
  also missing, as are bodies under 32 bytes and non-unique bodies.
- Bodies of 32 bytes or more can still collide with unrelated code. The review
  found no such case in its sample, but the risk is not zero.
- Relocation fields are masked, not resolved. No component gate claim.

- Generic Rust code (serde, futures, tokio, hashbrown and similar) is compiled
  inside the node's own crates. It can only be reproduced with the node's
  source, so it is first-party reconstruction work, not dependency matching.

- Unmatched RocksDB functions: every unique function in the GCC librocksdb.a
  that is still unmatched after relaxation was classified by whether its
  pre-relocation opening bytes occur in node115 `.text`:
  - 2,633 functions (1.58 MB) do not occur at all. Most are presumably removed
    by `--gc-sections` because the node never references them.
  - 931 functions (239 KB) have openings too short to test.
  - 37 functions (8 KB) occur only inlined.
  - 631 functions (1.12 MB) shared an opening with an FDE but differed later.
    After relaxation, 357 remain:
    - 232 are distinct template instances whose own symbol is credited at its
      real address (e.g. `FindFactory<SecondaryCache>` vs `FindFactory<EventListener>`);
    - 108 sit at an FDE already credited to the sibling instantiation that
      really occupies it;
    - 17 (5.4 KB) are unexplained. 14 of these are libstdc++ `std::function`,
      hashtable and red-black-tree instantiations with generic prologues. The
      other three are `port::Mutex::TryLock`,
      `ReverseBytewiseComparatorImpl::Compare` and
      `cassandra::ExpiringColumn::Expired`, whose prefix hit is a
      different-length function.
  - 452 functions are below the size gate or have several identical FDEs.

So no shared-prologue case shows a patched RocksDB or a different flag set. The
unmatched remainder is dead code the linker dropped (presumably), code too
short to test, inlined copies, or non-unique bodies.
