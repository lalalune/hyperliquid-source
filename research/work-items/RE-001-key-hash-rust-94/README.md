# RE-001: original-key hash across borrowed and owned storage

This extends the existing dependency-free `src/node94-alias` crate with the
bounded numeric function `key_hash(seed: [u64; 2], key: &[u8]) -> u64`. It closes
the original-key hash relation between the constructor lookup and insertion
wrappers. The associated ten-letter alias and inline carrier do not enter the
key hash. No cache API, target ownership type/ABI, runtime seed, allocation,
complete constructor or component gate is recovered.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source starts at published inline commit `743257a699da958290d18dd89825c7a1804f58b8`;
upstream main is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Coordinates are
original ELF VAs, exclusive ends. New code is independently authored from the
instructions and existing independently reconstructed feed; no inferred source
is copied. Cargo manifest/lockfile and dependencies are unchanged.

## Native evidence and conditional relation

| Role | Exact FDE extent | Bytes | GNU = LLVM rows |
| --- | --- | ---: | ---: |
| Borrowed-key wrapper | 0x13d38c0..0x13d3a20 | 352 | 90 |
| Owned-key wrapper | 0x13d3c80..0x13d3deb | 363 | 93 |
| Previously credited feed | 0x13daa30..0x13dac07 | 471 | 141 |

`native.json` binds the whole artifact, exact FDE/CIE/index/LSDA records, all
1,186 body bytes, both full exports, six direct calls, constants and exact caller
operands. Only the wrappers' 715 bytes are newly selected; the feed, constructor
and earlier insertion context are credited, with no whole-component denominator.
GNU objdump/readelf 2.44 and LLVM objdump 19.1.7 statically decode the bytes.
No captured program or captured-instruction evaluator is run.

The borrowed wrapper takes seed pointer RDI, key pointer RSI and u64 length RDX.
The owned wrapper reads a pointer at descriptor +8 and length at +16; capacity
+0 and associated alias bytes are not read. Both load the supplied 16 seed bytes
with MOVDQU (k0/k1 are little-endian u64 words at seed offsets 0/8),
initialize logical words
`[C0 xor k0, C1 xor k1, C2 xor k0, C3 xor k1]`, and call the same feed twice:
original key bytes, then one byte `ff`. No alias counter is appended.

The finalizer suffixes `0x13d392c..0x13d3a20` and
`0x13d3cf7..0x13d3deb` are identical 244-byte strings, SHA-256
`8840f248c1d348b0fdb0d6bd2760496dad7361362c5fbc2b2ef253e38fb9a209`.
They compress `tail | ((total & 255) << 56)`, xor `ff` into logical v2,
perform three rounds and xor all words. Physical order is v0,v2,v1,v3.
`equations.py` implements separately scheduled logical bulk and physical-order
incremental word equations, with wrapping u64 arithmetic. It has no decoded
opcode dispatch, register machine or captured-code execution.

Thus equal readable immutable key bytes/length and equal stable seed bytes
produce equal u64 results across the two wrappers. Native frames/state and
ALL live scratch, saved-register and return machinery must remain valid and
protected from the input objects; descriptor/key bytes must not be overwritten
by frame/state writes. Normal stack alignment for MOVDQA is a premise. This
is a conditional numeric equality, not a proof of original allocation, source
preservation or ownership.

Constructor `0x1449b36` forms seed address `0x577ae58`, then calls borrowed hash
at `0x1449b47`. Constructor `0x1449e15` forms table `0x577ae38`; insertion
`0x141b81d` adds +0x20 and calls owned hash at `0x141b82c`, selecting the same
seed address. These 16 file-backed .data bytes are zero in the ELF, and no
RELA entry targets the interval. Their runtime value, writer/provider, lifetime
and stability between lock phases remain unknown. Original-to-owned copy only
preserves keys under the still-open allocator/copy/source/nonalias premises.

Constructor inputs <=16 take #1577's inline route without these cache hashes.
The <=16 fixture rows below diagnose the hash wrappers only. For long inputs,
lookup/insertion hash original input bytes rather than alias letters/carrier.
Hypothetical mask31 slots and H>>57 fingerprints in `frozen.json` do not prove
runtime seed values, table mask/bounds, probing, equal-key replacement or cache
reachability.

## Frozen expectations and prior ownership

`PLAN.json` is the historical pre-Rust freeze, including its deliberately
historical `new_rust_written: false`. It binds `frozen.json`, the native records,
scalar equations, exact input/expected streams and the before-edit source.
The new Rust implementation and compiled receipt were created afterwards.

All 48 paired borrowed/owned numeric outputs were frozen before Rust: three
supplied seeds, lengths 0/1/7/8/15/16/17/31/32/63/64/65/255/256/257, plus 17 A
bytes. Thirty are conditional >16 constructor inputs; eighteen diagnose helper
behavior outside the constructor cache route. All after-key/after-ff states and
final words agree between the independent equations. Capacity len/len+1/len+16
has 144 unchanged projections; nine associated-value substitutions preserve H;
fifteen wrong-key/seed/delimiter controls change H. These controls are static
mathematical deductions, not reachable-state or allocator claims.

For 17 A bytes and supplied zero seed, H is `c5ff55238c99a3a2`. Substituting
alias letters PRZKHGDETU as the key gives `5cf0d6a7eb7822a3`. Their hypothetical
mask31 slots differ, 2 versus 3. Changing only associated value bytes leaves H
unchanged because the native wrappers do not load them.

Credit the merged RE-001 alias feed/finalization discovery, #1577's admitted
inline route, merged #1077 and open #1460's fixed20 round mathematics. Their
fixed20 outputs do not transfer: this wrapper hashes key20 plus ff, length21.
Three frozen domain controls differ. Existing `node94-keyed-mix` at 0x399c600
is a different fixed20 multiply/XOR helper with no selected call edge here.
`ownership.json` records a fresh search of 245 full open PR bodies with no
selected address/hash-bridge hits; unpublished work remains unknown.

## Authored Rust and actual comparison

The 21-line function initializes seed lanes on `AliasFeed::new()`, writes key,
writes ff, and finishes. It adds no new crate, allocation, unsafe code,
dependency, seeded public mutable state or descriptor representation.

`input-only.rs` receives only case IDs, supplied seeds and original key bytes.
Expected hashes are not passed to it or embedded in that driver. The actual
production function runs on a borrowed slice and three copied Vec slices with
requested capacities len/len+1/len+16. This tests safe copied inputs; Rust Vec
allocation is not the native allocator or descriptor ABI. Each profile checks
192 complete u64 results against 48 independently frozen expectations.

The qualifier binds all compiler-read project sources through dep-info, eight
source/input files, 68 selected compiler/std/linker providers and every frozen
input/expected byte in an immutable snapshot. Seven mutants are derived from
that exact Rust source. Baseline and all mutants compile at opt0/3; raw actual
outputs are compared, never overwritten with expected answers. `raw-streams.json`
is a lossless text encoding of 132 inert input/output/log members, with no
executable, rlib/object, copied source or captured artifact bytes. Compiled
products remain ignored/private.

The source change also causes a separate honest requalification of #1577's
original 156 native rows/two API refusals/six controls. Its original receipt and
source are retained historically at 743257a6 and in `historical.json`; the fresh
current-source receipt is not substituted for those old observations.

See [RESULTS.md](RESULTS.md) for exact receipts and checks. No hosted CI, whole
suite on this head, machine-code identity, full alias/cache or component gate
is claimed. Runtime seed, allocator/free/imported copy, source stability,
locking, equal-key replacement/deallocation, display, native faults/unwind and
complete constructor remain open.

## Reproduce

With authenticated node94, existing pinned Rust 1.94.1 and native tools:

```sh
python3 -I -B research/work-items/RE-001-key-hash-rust-94/verify.py
python3 -m unittest discover -s tests -p test_alias_key_hash_rust94.py -v
cargo test --locked --offline --manifest-path src/node94-alias/Cargo.toml
cargo test --release --locked --offline --manifest-path src/node94-alias/Cargo.toml
python3 -I -B research/work-items/RE-001-key-hash-rust-94/verify.py --qualify work/key-hash-fresh
cd research/work-items/RE-001-key-hash-rust-94
sha256sum -c MANIFEST.sha256
```

From the repository root, required checks are `make doctor`, `make verify`,
`make catalogue-check`, and `make reproduce`. The older alias captured-instruction
evaluator is not part of this follow-on and is not run here.
