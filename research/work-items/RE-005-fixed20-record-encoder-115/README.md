# RE-005: node #115 whole fixed20-prefix / four-scalar wire type

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; serialization / RE-005.
Addresses are half-open ELF VAs, no rebasing or registered byte masks. New Rust
and research are MIT. Existing licensed scalar primitives are reused without
new primitive or byte-credit claims; no inferred unlicensed code is copied.

## Gap, whole type and full contexts

The base supplies scalar size accounting. The preceding writer supplies one
u64 primitive. Neither supplies this concrete fixed20-byte/four-word type or
its actual parent dispatch. This packet closes the entire value-specific
count and writer, its fixed-copy contract, partial failures and calling context
as one contribution. It is distinct from the earlier eight-word/raw-trailer
type and from the two-scalar/fixed2048-byte decoder.

| Complete FDE | ELF VA range | Bytes |
| --- | --- | ---: |
| Whole record writer | 0x5967d90..0x5967e75 | 229 |
| Whole record size owner | 0x5967e80..0x5967f61 | 225 |
| Actual fixed20 copy helper | 0x58221e0..0x5822256 | 118 |
| Actual fixed20 size helper | 0x58223a0..0x58223cb | 43 |
| Actual scalar counter | 0x5822b90..0x5822c44 | 180 |
| Actual scalar byte writer | 0x5822910..0x5822b90 | 640 |
| Actual vector growth | 0x5963a10..0x5963a9e | 142 |
| Actual layout/allocation adapter | 0x5963650..0x5963739 | 233 |
| Complete selected parent | 0x5823db0..0x58241e1 | 1073 |

The denominator is **nine FDEs / 2,883 bytes / 764 instructions**. Complete
Capstone5.0.7 / GNU2.45 / LLVM23.1.4 partitions agree, and GNU readelf confirms
all actual FDE extents. Repeated dependency and parent context is not new
compiled-byte coverage or a whole-component denominator.

## Native field mapping and exact bytes

The writer first adds0x20 to its source pointer and calls0x58221e0, then reads
QWORDs from original source offsets0,8,16,24 and calls0x5822910 in that order.
The size owner follows the same ordering: fixed+20 at0x58223a0, then the four
scalar counters. Thus native memory holds four words before twenty bytes,
while the **wire puts the twenty bytes first**. The Rust struct expresses
logical wire values, not an asserted private source layout.

The complete copy helper checks vector capacity-minus-length against19, and
calls actual growth with additional20/alignment1/element-size1 when necessary.
Only after that reserve returns does0x58221f9..0x5822215 copy the final DWORD
at byte16 and the first sixteen bytes by unaligned XMM load/store, advance
length by20 and report raw success QWORD8. Neither copy changes byte order.
There is no encoded length prefix, byte swapping or semantic header transform.
The new implementation copies actual bytes, not a mocked memcpy.

The fixed-size helper checks count+20 for overflow and stores the complete
increment once, before any scalar. A prefix overflow leaves the old count;
a later scalar overflow leaves the prefix and prior fields counted, plus the
scalar's marker increment when its payload addition overflows. No whole-record
preflight or rollback is equivalent to those observed partial states.

All four scalar encodings retain the established1/3/5/9-byte contract. Their
actual vector reserve happens after a marked scalar's first byte is initialized.
Prefix reserve failure copies no prefix bytes; later failures retain the full
prefix and any earlier words/current marker. Errors identify logical boundary
snapshots; the original fatal/panic path is not assumed recoverable.

## Concrete parent and data closure

The complete parent0x5823db0 has two signed-relative five-entry tables at
0x935c44 and0x935c58. `dispatch.json` retains raw bytes and all actual targets;
the verifier freshly checks every target is an instruction boundary. Raw
index2 selects size arm0x5823e67 (call0x5823e71 to0x5967e80) and byte arm
0x5823fdb (call0x5823fff to0x5967d90). The byte arm writes and commits its own
raw byte2 before calling this child. The parent's size pass starts its counter
with one. This establishes real integration without adding the outer byte to
the child's independent API.

The size source is obtained through the parent's selected descriptor pointer;
the byte source is forwarded from its entry RCX through R15. Their complete
application identity and all other parent variants remain open. We do not
infer a full parent schema or assert concurrent/source-view equivalence.

`records.json` retains the actual direct calls, branches and RELATIVE writers
through the full scalar/growth/allocation contexts. Byte-vector growth follows
max(8,2cap,length+additional) in the selected element-size1 domain. Its raw
allocator adapter checks layout bounds before backend calls. Backend identity,
returned addresses, fatal/unwind payloads and original Vec/Result ABI remain
external boundaries; the new code uses actual `alloc::Vec` and allocation.

`locations.json` freshly resolves0x64b0ef0 through its actual RELATIVE writer to
embedded `z_forks/bincode-fork/src/enc/write.rs:78:9`. This is source attribution,
not a guessed public release. Twenty-three actual instruction/table/Location
anchors, including both parent tables, are independently corrupted and must be
rejected; two wrong target identities are separately rejected. No mutated
captured instruction executes.

## Real, licensed dependencies

`scalar/` contains the exact project-authored MIT source from
[PR2809](https://github.com/lalalune/hyperliquid-source/pull/2809), commit
`e685a25fae1dcd5b12fa89449e1a5c4c66c91b7e`, with LICENSE, whole source hash,
original path and immutable commit in `PROVENANCE.json`. Its library source is
unchanged; only a private package manifest/library path is adapted.

The `counter/` manifest points at the real unchanged base
`src/node115-varint-size-state/lib.rs`, hash-bound in its provenance. Both are
actual buildable path dependencies, not stubs or references to an unmerged
checkout that reviewers cannot build. No original workspace/crate graph or new
primitive completion is claimed. Safe Rust borrows/arrays exclude invalid raw
source spans, pointer ownership and source/output aliasing domains.

## Independent pre-Rust expectations and qualification

Before new Rust existed, `oracle.py` froze **32,266** whole-record observations.
Original TSV SHA-256:
`bbe47b0a812ad607d41794ed9441a74cf1598c5290616b63cf3a813fc82a6dcb`.
Lossless gzip(mtime0) hex was packed before Rust. The qualifier decompresses,
authenticates those exact bytes and independently recomputes ordered event,
count and growth mathematics. No captured instruction evaluator is invoked.
Existing scalar source predates the freeze and is disclosed.

Cases cover all four positions and scalar width thresholds, exact20-byte
prefix budget/capacity boundaries, every possible initial-count overflow stage,
all256 seeded prefix byte patterns, nonempty output prefixes, and actual first
through fourth allocator-request refusal. Real System-backed GlobalAlloc
fault injection refuses only a selected request during the independently
authored Rust call. Actual Vec storage/capacity/length/request count are tested;
there is no mock Vec, resource exhaustion or captured-node execution.

Debug and release builds each match all32,266 rows. Nine compiled type-level
mutants exit normally and mismatch: prefix size19, reversed size fields,
missing fourth field, reversed wire fields, reversed prefix, nineteen-byte
copy, piecemeal prefix allocation, rollback on field error and whole-count
preflight. The piecemeal-copy and rollback controls check real retained bytes, not a
self-reported trace. Exact mismatch/source records are in `qualification.json`;
original logs and outputs are retained under ignored
`work/environment/eight-batch/fixed20-record/qualification/`.

```
python3 -B research/work-items/RE-005-fixed20-record-encoder-115/verify.py
python3 -B research/work-items/RE-005-fixed20-record-encoder-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-fixed20-record-encoder/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-fixed20-record-encoder/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-fixed20-record-encoder/Cargo.toml
```

Only independent host Rust executes; the Linux rlib is built but not run.
No captured execution/emulation, node networking, captured-node OS calls,
chain actions, original ABI or byte-equivalence claim exists. All full-scope
gates and byte totals stay unchanged. Next recover the selected parent's other
value types and source-view/lifecycle contract before a complete parent claim.
