# RE-005: node #115 complete eight-word/raw-byte wire type

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; serialization / RE-005.
Ranges are half-open ELF VAs, with no rebasing or registered byte masks. New
code and research are MIT. Existing project-authored MIT scalar primitives
are explicitly reused, not re-credited. No inferred unlicensed source is copied.

## Gap and selected whole type

The base has scalar size accounting. The preceding byte-writer contribution
adds one u64 primitive. Neither reconstructs this complete ordered eight-word
record and final raw byte, its size traversal, or its actual parent use.
This packet closes those type-specific semantics together, not one field or
size helper in isolation. Application type names and units are unknown.

| Complete context | ELF VA range | Bytes |
| --- | --- | ---: |
| Whole record size traversal | 0x5967f70..0x596809e | 302 |
| Whole record byte writer | 0x59681d0..0x5968332 | 354 |
| Actual u64 size callee | 0x5822b90..0x5822c44 | 180 |
| Actual u64 byte callee | 0x5822910..0x5822b90 | 640 |
| Actual growth helper | 0x5963a10..0x5963a9e | 142 |
| Actual allocation/layout adapter | 0x5963650..0x5963739 | 233 |
| Complete parent serializer context | 0x5822c50..0x5822f69 | 793 |

The denominator is **seven FDEs / 2,644 bytes / 679 instructions**. Complete
Capstone5.0.7 / GNU2.45 / LLVM23.1.4 partitions agree; GNU readelf confirms
actual FDE extents independently. Repeated primitive/parent context supplies
no new byte-equality or full-component completion credit.

## Observations and type-specific reduction

The size owner reads source offsets0,8,16,24,32,40,48,56 in that order and calls
0x5822b90 eight times on the same counter at its entry state+0x10. Every normal
return requires raw success QWORD8. The final sequence0x5968059..0x596806f
adds one to that same counter with a separate overflow-helper edge. It does
not dereference the trailer value; all possible trailer bytes have size one.

The byte owner repeats those eight source loads and calls0x5822910 on the
same vector at entry state+0x10. At0x59682c7 it loads a pointer from source+0x40,
then **one byte from that pointer**. It performs no bool test, byte masking or
varint classification on that byte. After any needed one-element growth, the
byte is written unchanged and vector length commits. This establishes the
logical `words:[u64;8], trailer:u8` value. It does not recover the native
pointer's ownership, lifetime or source-language field names.

An allocation refusal while writing any scalar retains all preceding fields
and any prefix marker that callee committed. A trailer-growth refusal retains
all eight encoded words. A size overflow similarly preserves prior fields and
that scalar's marker increment; the trailer increment has its own boundary.
Safe enums report the field index or trailer stage for inspection, rather than
claiming the native fatal/panic path returns an error.

## Actual parent and helper/data closure

The parent0x5822c50 copies four XMM words from its parent object+0x140..+0x180
into a 64-byte temporary and stores the address parent+0x180 at temporary+0x40.
Its call at0x5822cd7 reaches this exact size owner. The second-pass setup reloads
the same source region and trailer address, then call0x5822e47 reaches this
exact byte owner. `records.json` retains the full parent, its call graph and
argument setup bytes. The enclosing object has other serializers outside this
selected type; no complete parent schema or concurrent reread behavior is
claimed.

The u64 writer's complete branches encode1/3/5/9 bytes and preserve a committed
marker before a payload reserve. Its real byte-vector growth computes
max(8,2cap,length+additional), with checked required length and native allocation
layout bounds. The retained allocator adapter and real RELATIVE slots bind its
backend/failure boundaries; backend identity and panic ABI remain open.
Original compiler/allocator addresses and binary identity are not reproduced.
The new implementation operates on real `alloc::Vec` and actual Rust allocation.

`locations.json` freshly resolves the actual counter-overflow Source Location
at0x64b0ef0 through its RELATIVE writer to embedded
`z_forks/bincode-fork/src/enc/write.rs:78:9`. This attributes source, not an
exact dependency checkout or public crate version. Original source/License
hashes, call targets, body extents and27 selected instruction/data anchors are
checked mechanically;27 actual anchor corruptions and two wrong identities
must be rejected.

## Real, pinned reuse

The standalone crate contains an exact MIT source snapshot of the previous
project-authored u64 writer from [PR2809](https://github.com/lalalune/hyperliquid-source/pull/2809),
commit `e685a25fae1dcd5b12fa89449e1a5c4c66c91b7e`, under `scalar/`. Its LICENSE,
source hash, original source path and immutable commit are recorded in
`PROVENANCE.json`. Only its private package manifest's library path is adapted;
the old probe binary is not imported. Its Rust source is unchanged.

The `counter/` private manifest points at the actual existing MIT base source
`src/node115-varint-size-state/lib.rs`, with a hash-bound provenance record.
Both are real Cargo path dependencies that build from this independent branch;
no absent pending-PR path, registry stub or recovered original workspace is
invented. No primitive, allocator or counter completion credit is counted anew.

## Pre-Rust expectations and actual qualification

Before the new crate existed, `oracle.py` froze **43,325** whole-record cases.
Original TSV SHA-256:
`9aaa7619f4b3d7aefa24ab98a0185f10f86811372c8beb50d3974f8625ccb4c5`.
Lossless gzip(mtime0) hexadecimal storage was packed before Rust. The qualifier
first decompresses and authenticates those exact bytes, then independently
recomputes mathematical ordered events/counts. Existing scalar implementations
predate the freeze and are disclosed; no captured instruction evaluator runs.

Inputs cover every field position, all scalar width thresholds, partial-count
overflows through each field and trailer, all256 raw trailer bytes, existing
vector prefixes, exact trailer-capacity boundaries and first through fifth
allocation refusal. Debug/release actual builds both match all cases. The host
probe forwards real alloc/realloc/dealloc operations to System and refuses only
a selected request during the new library call. Thus actual Vec failure, bytes,
capacity and lengths are checked; no mock Vec or resource exhaustion is used.

Eight actual compiled type-level mutants exit normally and mismatch: reversed
size field order, missing eighth field, reversed wire field order, bool trailer,
trailer insertion before the record, omitted trailer count, byte rollback on a
field error, and whole-size preflight. Dependencies remain genuine and unchanged.
Original builds/stdout/stderr are in ignored
`work/environment/eight-batch/octet-record/qualification/`; exact mismatch and
source identities are in `qualification.json`.

```
python3 -B research/work-items/RE-005-octet-record-encoder-115/verify.py
python3 -B research/work-items/RE-005-octet-record-encoder-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-octet-record-encoder/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-octet-record-encoder/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-octet-record-encoder/Cargo.toml
```

Only independently authored Rust executes on the host; the Linux rlib is built
but not executed. No captured execution/emulation, node networking, OS/chain
actions, original ABI, complete parent serializer or byte-equivalence claim
exists. All full-scope gates and byte totals remain unchanged. Next resolve the
enclosing parent schema and the meaning/ownership of the eight words and raw byte.
