# RE-012: node #115 complete conditional LZ4 match-sequence stage

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; transport / RE-012.
All coordinates are ELF VAs, half-open bounds, no rebasing or normalization.
New code and research are MIT. The static verifier is adapted from the author's
repository-MIT packet [PR2771](https://github.com/lalalune/hyperliquid-source/pull/2771),
head `8ede1e78eb0b18d0faeb5dea619a566b73d4221c`; all exports are freshly
regenerated. No public codec or unlicensed inferred implementation was copied.

## Missing result and scope

The base has a size-prefixed decoder. Earlier contributions reconstruct the
final literal emitter, dictionary probe and forward match extension. They leave
the selected compressor's actual matched-sequence output open. This packet
implements the **whole conditional emission stage** shared by both compressor
FDEs, including token, both excess lengths, literals, offset and partial sink
state. These operations form one outcome; offset and match excess are not split
into separate contributions.

The stage is inlined, so it has no invented native FDE. Complete small and large
contexts are `0x477e950..0x477f036` and `0x477f040..0x477f746`. Their real
literal-copy helper is `0x477e5c0..0x477e6d4`. The explicit static denominator
is three complete FDEs, **3,840 bytes / 883 instructions**. These are repeated
context or new semantic interpretation, not new registered equality credit.
GNU2.45, LLVM23.1.4 and Capstone5.0.7 agree on complete partitions. GNU readelf
and the repository unwind parser independently confirm the extents.

## Binary observations and field mapping

| Stage | Small entry | Large entry | Logical effect |
| --- | --- | --- | --- |
| Token guard and two nibbles | 0x477ec19..0x477ec5b | 0x477f328..0x477f369 | min(literal_count,15)<<4 OR min(additional_match,15); one committed byte |
| Literal excess | 0x477ec65..0x477ed28 | 0x477f373..0x477f438 | repeated 255 followed by remainder 0..254 |
| Valid literal span and append call | 0x477ed28..0x477ed46 | 0x477f438..0x477f456 | both append length arguments equal literal count |
| Offset checked addition, capacity, WORD store | 0x477ed4b..0x477ed79 | 0x477f45b..0x477f489 | one LE16 distance, whole two-byte capacity check |
| Match excess branch and stores | 0x477ed7d..0x477ee59 | 0x477f48d..0x477f569 | additional_match >=15 uses the same 255/remainder convention |

The literal count is match-start minus saved literal anchor, checked before
emission (`0x477eb76..0x477eb96`). The initial match is already four bytes;
actual calls at `0x477ebb5` and `0x477f2b5` return the **additional** match
count. Small code saves RAX at `[rsp+0x48]`; large code uses `[rsp+0x20]`.
Those different stack slots are retained in full contexts, rather than guessed
from a uniform source layout. The low token nibble and match extension encode
that additional count, not total match length.

The distance remains in RBX and is stored through BX. Its earlier candidate
probe restricts distance below 65536; this API therefore accepts a u16. The
selected local emission stage does not reject distance zero. Emitting zero
locally does not prove a valid complete compressor path or a decoder-accepted
block. Dictionary stores, backward extension, search/skip behavior and match
selection precede this stage and are expressly conditional.

## Copy, failure and data closure

The sink is observed as pointer/capacity/used fields at +0/+8/+0x10. Each token,
individual extension and complete literal/offset stage updates used length.
A later refusal retains all earlier stores. The append helper checks addition
and whole literal capacity before copying; it cannot copy a truncated literal
prefix on capacity refusal. The offset stage checks used+2 and its complete
capacity before its WORD store; one remaining byte is left untouched.

`copy-relocation.txt` independently resolves slot `0x64df508` via its actual
`R_X86_64_GLOB_DAT`, dynamic-symbol index7, and linked string table to
`memcpy@GLIBC_2.14`. Small copies are inlined within the retained append FDE;
long copies cross that external byte-copy boundary. Safe Rust uses a real
`copy_from_slice` with disjoint valid slices, not a mocked helper or a forged
Cargo dependency. Original memcpy ABI, allocator ownership and panic objects
are not reconstructed.

`locations.json` binds selected source Location records to actual RELATIVE
writers and embedded `lz4_flex/src/sink.rs` / `block/compress.rs` paths. A path
is attribution evidence, not an exact public crate version or proof of an
unmodified dependency. `verify.py` checks these raw records/writers, filenames,
copy symbol, complete call/branch contexts and 31 instruction/data/symbol
anchors. It rejects 31 actual anchor-byte corruptions below the full-target
identity guard, plus two wrong identities. No altered target code executes.

The safe API takes a valid literal slice, so original invalid raw source-span
and pointer domains are excluded, not reclassified as an invented native error.
It adds an explicit `Domain` refusal for used>capacity. `Error` variants label
failure stages and do not assert native enum tags, panic payloads, unwinding,
catchability or continuation after a native failure helper.

## Scalar reduction of grouped stores

Both native excess loops use multiplier C=`0x8080808080808081` and high-product
shift7. C*255=2^71+127 and ((2^64)-1)*127<2^71, proving
floor(x*C/2^71)=floor(x/255) for every u64 x. Applied to excess-255, the computed
number is one less than the required FF count q. The grouped path emits
4*floor(min(q-1,free)/4) FF bytes, leaving the remainder to the scalar loop.
All grouped stores fit capacity. Grouped plus scalar completed FF bytes equal
min(q,free), with the same required remainder-byte refusal when capacity ends.
`qualify.py` checks the exact reciprocal premises and 264,196 quotient/free
prefix combinations. This proves logical byte and used-count behavior, not
identical stores, speed or asynchronous-fault visibility.

## Independent pre-Rust expectations and results

`oracle.py` constructs mathematical token/extension/literal/offset events, then
applies capacity to each event. It uses division/remainder and whole payload
or repeated-byte events; production Rust emits scalar bytes directly. Before
the new Rust directory existed, **38,856** cases were frozen in `cases.tsv`.
`freeze.json` retains that historical false-existence flag, generator hash and
fixture SHA-256 `2204ec4f23de5cfdd4017f729996069e45cb5feafa289d8855c69681efddc9fc`.

Cases cover both nibble thresholds, exact 255 multiples and neighboring values,
grouped-store thresholds, literal sizes through4096, offset byte ordering,
zero/65535 distances, initialized sink prefixes, each capacity boundary and
adapter-domain rejection. u64::MAX additional-count cases test the conditional
integer stage and bounded-capacity refusal; they do not claim such a count is
reachable from an allocated native source slice.

Actual Rust1.95.0 debug and release builds match every frozen observation,
including the **entire sink**, untouched suffix and final used length. Eight
actual compiled production mutants attack literal nibble, initial-four
accounting, offset endian, required zero byte, match threshold15, partial offset
copy, partial literal copy and whole-operation preflight. Exact outcomes,
first mismatches and source hashes are in `qualification.json`; original
compiler/stdout/stderr files remain under ignored
`work/environment/next-ten/match-sequence/qualification/`.

```
python3 -B research/work-items/RE-012-lz4-match-sequence-115/verify.py
python3 -B research/work-items/RE-012-lz4-match-sequence-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-lz4-match-sequence/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-lz4-match-sequence/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-lz4-match-sequence/Cargo.toml
```

Only newly compiled independent Rust runs on the host. The Linux rlib is built
but not executed. No captured execution/emulation, socket, chain action,
complete compressor, original ABI or byte-equivalence claim exists. All
full-scope gates and compiled-byte totals remain unchanged. Next close the
complete caller initialization/search/backward-extension state and integrate
these actual helper contracts into a whole compressor.
