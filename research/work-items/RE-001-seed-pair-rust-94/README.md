# RE-001: one-time logical alias seed-pair factory

The existing dependency-free `src/node94-alias` component adds
`next_seed_pair(source: &mut [u64; 2]) -> [u64; 2]`: return the old pair and
wrap-increment only source word0. The caller uses the returned pair once for a
cache initialization and keeps that installed seed stable for later `key_hash`
calls. The API does not enforce this lifecycle. It is never called inside
`key_hash` and must not advance the source once per key.

This is a logical value projection of an already-ready source, not native TLS
access, a cache/closure type, entropy, Once synchronization or original ABI.
Node94 target: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source begins at published #1577 head `a994e34ee93686fd5c097d76f7e2083ba1f0659f`;
all addresses below are original ELF VAs, exclusive ends. New code is authored
from authenticated native evidence; no inferred source is copied. Existing
Cargo manifest, lockfile and dependencies are unchanged. No component gate moves.

## New native question and closed normal path

| Selected complete FDE | Bytes | GNU = LLVM rows |
| --- | ---: | ---: |
| Callback 0x1447590..0x14475f0 | 96 | 25 |
| Initializer 0x1452070..0x14520d5 | 101 | 26 |

Only these 197 bytes are newly selected. Generic Once at 0x4ee3b20..0x4ee3d3c
is credited to RE-001-once-state-94; constructor context, alias/feed and #1577's
inline/key-hash work remain credited. `native.json` binds exact FDE/CIE/index
records, all complete bodies, source sites, constants and four actual RELATIVE
records. GNU binutils 2.44 and LLVM objdump 19.1.7 agree on all 51 selected rows.
No target program or captured-instruction evaluator runs.

Constructor init branch 0x1449e73 supplies Once pointer 0x577ae68, force 1,
captured object 0x577ae30 and vtable 0x566a7b8. The exact +0x20 relocation selects
callback 0x1447590; the initial object function-word relocation selects initializer
0x1452070. With Once raw state 3, successful uncontended CAS claims1, supplies
local poison byte 0, invokes this callback and later publishes0 without a futex call.
These are observed values, not a reconstructed synchronization API.

Let b be valid load bias, O=b+0x577ae30 and E=b+0x202e90. The initializer tests
BYTE FS:[-0x460]. For a nonzero byte, it loads the old two-qword pair at
FS:[-0x470], then INCs only its first qword, and writes the OLD pair to local
output+0x28/+0x30. Other output words are [0,E,0,0,0]. The callback copies all
56 bytes to O, so seed slots O+0x28/O+0x30 receive the old pair. The TLS source
increment does not change the installed seed under the qualified separation.

The selected normal relation requires valid relocated pointers and mapped
spans, exclusive/no-observer access, successful uncontended Once3 entry, and
separation of TLS/global destinations from prepared output and protected live
frames/saved-register/return storage. Prepared output and capture slots may
occupy their declared frame locations; only their explicit native writes are
allowed there. No intermediate-store/observer equivalence is claimed.

Flag 0 calls 0x13c8970; its source provider 0x4ee4360 and the slow caller's
`FS:0 == FS.base` premise remain unproved and excluded. Poison/state 2,
waiter/state 7, failed CAS, runtime entropy/readiness, seed/global lifetime,
allocator/copy/free, table/probing/equal-key behavior and full cache ABI stay open.

## Freeze, static controls and Rust scope

`native-freeze.json` retains the accepted pre-model seven full 56-byte-output /
24-byte-TLS frames. `PLAN.json` freezes their pair projections and exact
input/expected streams before the new Rust source. Historical fields saying
`new_rust_written: false` identify that freeze, not the current implementation.
Cases include zero, asymmetry, carry32, u64 wrap, signed-boundary, high-bit and
near-wrap. Raw readiness bytes 2/128/255 are guard diagnostics, not claimed
runtime values or an original bool/enum domain. E=0x202e90 is the explicit b=0
coordinate witness, not an observed ASLR address.

The static verifier binds complete native bytes and applies only four explicit
operand fields to dedicated word equations. It has no instruction dispatcher,
register machine or captured execution. All four pre-frozen controls are
operative: branch inversion changes route classification only; wrong SIMD
destination gives [E,0]; m64-to-m32 INC preserves the wrong high32 on carry;
INC-to-DEC changes the subsequent source. Excluded routes get no invented output.

The Rust implementation covers only the returned old pair and subsequent
source pair. It does not implement the native 56-byte metadata record, callback
stores or TLS/frame representation. Seven compositions reuse the returned seed
for two hashes of 17 A bytes; prior key-hash mathematics is credited. Three hash
expectations were already frozen in #1577; four were independently derived
before new Rust with its existing logical/physical word equations.

## Actual compiled evidence and history

The input-only driver receives case IDs, pair values and key bytes, never
expected answers. Baseline and seven source mutants compile at opt0/3 from one
fixed snapshot: all 16 builds/32 compiler commands succeed without diagnostics.
All7 pair/composition results match, with7,7,7,3,7,6,7 differing cases for the
seven mutants in each profile. Actual stdin/expected/observed streams, exact
compiler logs and dep-info are retained as text. `qualified-runner.py` is the
byte-exact owned source used for those observations, not a newly relabeled run.

Only the identical driver artifact moved from its recorded ignored-work path
into this packet. Verification explicitly maps that one historical path to
`input-only.rs` by exact byte hash; current production source and every fixture
must still match their actual recorded paths/hashes. No source pin is relaxed.
The standalone archived runner expects its original work layout; use `verify.py
--qualify work/<fresh-name>` to materialize only authored preparation text/streams
under ignored work and repeat it. No fake crate/workspace is made.

Adding the factory changes the whole library. Published a994 inline 80cfc156 /
key-hash 1100279a remain historical and are indexed in their packets. Their
selected corpora were freshly qualified on actual current lib760f:
inline c727112a (156 native+2 API-only rows/six mutants/repeat products) and
key-hash a7261c5b (48 paired expectations/seven mutants). Original inline743
history is also preserved. No old run is presented as the changed-source build.

A first current-lib run stopped at its disk guard before opt3 and had no durable
per-build receipt; it is preserved and not reconstructed. Approved wrapper
11a29793 then serialized ACTUAL per-build receipt data atomically before cleanup
in fresh complete runs. `checkpoints.json` retains those literal partial
checkpoints, guard/cleanup audits and stop/success logs. Partial checkpoints are
not final success receipts. Only completed new nonbaseline products were removed
after comparison/hash; all baseline products and source/input/logs were preserved.
The wrapper change is limited to this demonstrated requalification blocker.

See [RESULTS.md](RESULTS.md) for exact hashes/checks and remaining gates.
No full suite on this head, hosted CI, target-code identity or full constructor
is claimed. No captured execution, installer, credential or security setting change.

## Reproduce

From repository root with authenticated inputs and existing tools:

```sh
python3 -I -B research/work-items/RE-001-seed-pair-rust-94/verify.py
python3 -m unittest discover -s tests -p test_alias_seed_pair_rust94.py -v
cargo test --locked --offline --manifest-path src/node94-alias/Cargo.toml
cargo test --release --locked --offline --manifest-path src/node94-alias/Cargo.toml
```

Optional authored-Rust comparison with installed pinned Rust 1.94.1 and enough
reserve (minimum 300MiB plus 16MiB transient headroom):

```sh
python3 -I -B research/work-items/RE-001-seed-pair-rust-94/verify.py --qualify work/seed-pair-fresh
```
