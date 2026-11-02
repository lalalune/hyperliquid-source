# RE-012: complete greeting reply wire variants

- Component: transport / serialization integration.
- Base: `b01cbf3c5c80391cdb9ee963d5d483039868e563` (initial frame exchange).
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Question: decode every outer greeting and nested hash wire variant, including
  logical limits, collections, invalid integers, truncation and suffixes.
- Result: independent Rust wire/value projection plus decoded frame-exchange
  integration. No original ABI, peer acceptance or complete node claim.

## What changed

`src/node94-tcp-frame/src/greeting/reply.rs` implements all six outer selectors
and all three nested selectors. `greeting::exchange` now composes the existing
frame exchange with this decoder, using the same caller-selected limit for
frame admission, LZ4 output and logical decode charge. The raw frame API stays
available. Invalid reply encodings become `ExchangeError::Decode`.

The parser uses the existing independent `src/bincode-varint` implementation,
with the selected wrapper's fast/slow boundary and error-code distinctions.
Its path dependency is enabled by `timed-stream`; the default codec remains
unchanged. Cargo generated the new lockfile entry. This is a real component
build, not a recovered whole-node dependency graph.

`CONTRACT.md` records the wire/value contract before implementation. Types and
field names are intentionally positional. The original nominal types, field
layout and discriminant layout are not inferred as a public Rust ABI. In
particular, the outer three-word variant keeps values in wire order, although
the target's output cells are second, third, first.

## Native scope and attribution

`anchors.json` binds 24 full FDE extents (14,559 bytes of retained context),
428 selected call/compare/arithmetic instructions, ten dispatch tables and
eight relocation records. Full GNU/LLVM exports and their exact commands are
retained. Linked ELF virtual addresses are used throughout; exported C++
labels printed by objdump are not function names or ownership evidence.
These are analysis extents, not matched reconstruction bytes.

The main corridor is `0x25618f0` (outer reply), `0x255eba0` (nested hash),
`0x1f646e0` (32 bytes/two maps), and `0x21cca20` (three records).
`0x2891c30` reads the byte vector. The three map readers are `0x2890b60`,
`0x28916c0`, and `0x2890ea0`; they use fixed-20 keys and `0x25587d0` values.
`0x2558ee0` reads four variable-width words after a single 32-byte logical
charge. `0x2559410` charges and reads exactly 2,048 raw bytes.

The kind-5 word reader at `0x2558d80` differs from ordinary u64 reads:
its invalid-integer expected code is 5 on both fast and slow paths. Its slots
`0x57745d0/0x57745d8` resolve to `0x466dad0/0x466dac0`. Ordinary u64 slots
`0x57745e0/0x57745e8` resolve to `0x466d980/0x466dac0`, and u32 slots
`0x5775138/0x5775140` resolve to `0x466d850/0x466dac0`. The verifier checks
full relocation tuples. The imported copy/compare slots are retained separately.

The target also carries the source path
`/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/alloc/src/collections/btree/node.rs`.
The three insertion wrappers compare 20-byte keys, replace equal-key values,
and delegate missing-key insertion to B-tree helpers. The independent parser
uses `std::collections::BTreeMap` for the logical sorted/last-value result;
its public [ordering and insert contract](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html)
is supporting source documentation, not target-byte identity. The documentation
page observed during this work was newer than the pinned build. The source
path is provenance, not proof that the whole target standard library matches.
No target tree-node, split/ancestor, allocator or drop-layout reconstruction is
claimed. Large-map unit cases validate the new logical implementation; the
independent map corpus below covers the previously qualified small-limit domain.

Prior work is credited rather than relabeled as new primitive recovery:

- `stream-msg-codecs-94` for the outer/nested schema and corrected 80-byte arm.
- RE-005 varint, slow-width and Reader Rust packets for integer primitives.
- PR #1723 (`72b7a41d30b40ef105c9fec5a713f6726162e5cb`) for the actual reply
  envelope, limit, active result fields and diagnostic consumed count.
- PR #1742 (`1e71cca655a54190a5d140a0ef890250025ed820`) for four-word and paired
  value semantics; PR #1779 (`cf7e74e68e58ed05817ea6f536d76ee4f306a453`) for the
  selected small-limit map; PR #1816 (`fd5a8af5a4c3f4985ddeabff116cb9a632d63290`)
  for the three records, full arrays and type-code-5 distinction.

Those proofs were inspected as leads and checked against the selected target
bytes. Their independently frozen data is used below; no peer implementation
or unlicensed can1357 source is copied. Earlier frame/deadline receipts remain
immutable and retain their original scope.

## Logical accounting and failure behavior

A selector charges four bytes regardless of its encoded width. Ordinary u64s
charge eight. Four-word groups charge 32 once, then the trailing map-value byte
charges one. Map count decoding charges eight, followed by a checked
`96 * original_count` reservation. Each original row refunds 96, then charges
20 + 32 + 32 + 1; duplicates still consume and charge their row. The byte vector
charges its decoded count and rejects counts beyond remaining input before
copying. Fixed fields charge before availability checks.

Overflow preserves the previous charge; a limit failure retains the increment.
Short fixed fields consume none. Short integer extensions consume only their
marker. Invalid integer markers remain unread on fast paths, but are consumed
by slow Readers. u32 selects fast above four remaining bytes; u64 above eight.
The last word of a four-word group still selects fast/slow; it is not forced
through the Reader. Every raw array/byte value is accepted.

A successful decoder may leave a suffix. The returned metadata reports actual
consumed/remaining bytes and charge. Failures expose actual cursor progress;
the target wrapper's separate error diagnostic is zero, not a cursor rollback.
No partial map or record is returned as success after a later field fails.

## Independent fixture comparison

The three original compressed corpora in `fixtures/` are copied byte-for-byte
from the pinned PRs. `sources.json` records origin, commit, path and full hash.
They are mathematical predictions frozen by their authors before their own
checkers, not outputs from executing the captured node. Original rights and
repository terms remain attached. The adapter executes only this independent
Rust parser; it does not import or execute the peer checkers.

The concrete validation task needed a caller for the newly composed decoder:
the existing primitive drivers do not expose full replies or this projection.
The small `replay.rs` stdin adapter and `replay.py` fixture runner supply only
that evidence interface; they introduce no node CLI or runtime architecture.

`replay.py` embeds selected zero-charge cases into real greeting envelopes and
`replay.rs` projects only defined logical fields. Prefix charges are 24 for
records, 84 before a paired map value, and 56 before a map. Paired-value cases
need limit at least 76 to admit the containing map reservation before reaching
the value. The comparison covers 35,023 cases: 10,051 record, 11,967 value and
13,005 map cases. This supplements the unit tests with independently supplied
word, array, truncation, key-order, duplicate, charge and error expectations.

An initial replay found two mismatches, retained in `replay-initial-result.json`.
They were adapter-domain errors: adding the required 56-byte prefix to the
standalone map's recorded near-u64-maximum reservation would overflow. A direct
full-greeting test checks that overflow without a counter store. Only those
two unrepresentable rebases are excluded and named in the final receipt;
source corpora remain unchanged. The initial compiler invocation also omitted
the dependency search directory; its error is retained under ignored work/
and the adapter now takes that directory from the actual Cargo artifact.

## Reproduce and validation

```sh
make doctor verify
python3 research/work-items/RE-012-greeting-reply-94/verify.py
python3 -m unittest discover -s tests -p test_greeting_reply_evidence.py -v
python3 research/work-items/RE-012-greeting-reply-94/replay.py
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
cargo build --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release --target x86_64-unknown-linux-gnu
make verify test catalogue-check reproduce
```

`VALIDATION.md` and build/replay receipts give actual results, source hashes,
commands and scope. Native checks authenticate the complete target and then
check the selected bytes/tables/relocations. Their counterfactual seam reuses a
fixed authenticated layout only for mutations of code/data under that layout;
it never grants authenticated origin. Compiled wrong-source controls test
semantic sensitivity separately from static byte integrity.

All component gates and registered byte windows remain unchanged. The new
parser provides decoded fields for future acceptance checks; it does not
recover their meanings, verify a peer identity, select endpoints, synchronize
state or build a node/Docker image. Node #115 and current-network drift remain
separate targets. The next integration is the caller's reply-variant handling
and peer-acceptance/retry policy, followed by bootstrap/state validation.
