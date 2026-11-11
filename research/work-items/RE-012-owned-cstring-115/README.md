# RE-012: complete selected owned CString conversion in Rust

Sole target Linux x86-64 node115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; foundation / RE-012.
Original ELF VAs, no masks/rebasing. New source/research MIT; no inferred
unlicensed reference source copied. Actual allocator probe harness is credited
reuse of the author's MIT earlier varint-writer probe, not new allocator credit.

## Before and selected complete outcome

Existing command-conversion research models only the converter scalar input
length<=15; longer scans are exported but unmodeled. Existing filesystem and
DB-prefix work records converter success/error as a boundary, without Rust.
This contribution independently reconstructs the complete selected byte-slice
converter141e960..141eada, all lengths/first-NUL paths, owned error copy and
normal terminator handoff. The return is safe Vec/Error, not original enum ABI.

At141e971 the native length+1 sign bound precedes allocation. It allocates
length+1 even for empty input and before knowing whether input containsNUL.
The141e9ad memcpy copies all original bytes before scanning. An interior zero
returns non-sentinel capacity/ptr/original-length plus its first offset; the
owned error copy does not append a terminator or truncate to that first offset.
Absent a zero,141ea70 stages capacity=len+1, pointer and original length and
calls RELATIVE64df690→141e170. That reachable finalizer stores one zero and
returns pointer/length+1; capacity is already exactly sufficient. The converter
then stores signed-minimum success sentinel. Neither UTF8 nor Unicode or slash
normalization is applied. Bytes including highbit values remain exact.

The generic finalizer's other reserve/shrink branches are retained context,
not claimed implemented for arbitrary raw vectors. This constructor's exact
len+1 capacity never selects them. The source disjoint slice/ownedVec domain
excludes malformed pointers/capacity/aliasing. Error::Allocation is a safe
projection of the native size/allocator failure boundary; original fatal/
panic/unwind behavior and allocator addresses are not claimed. Actual native
caller destruction/clear-first-byte behavior and OS callbacks remain outside.

## Scalar, aligned scan and first-zero proof

For length<=15 the complete scalar loop returns the first zero. For longer
inputs it scans a0..7byte alignment head, pairs of8byte words and a scalar
tail/refinement. A suspected16byte block is refined from its beginning, so
word detection need not and does not manufacture a zero index from a bitmask.
For each word x, C=0x0101010101010100 and H=0x8080808080808080;
`(((C-x) mod2^64)|x)&H == H` exactly when every byte is nonzero. Byte0 of C
is0: any nonzero low byte creates borrow1. With no earlierzero, every later
nonzero byte propagates that borrow and either x or its negation has highbit1.
At the first zero, the subtraction byte and x both have highbit0. This proves
the all-word identity, not only sample consistency; two words are combined
withAND, so either containing zero selects refinement. Head/block/tail intervals
cover every byte once under the observed length>15 admission and valid span.

`derive.py` reads actual immediates under whole-body identity, rejects each of
16actual constant-byte mutations, checks459008 two-adjacent-byte/uniform word
relations and8072 alignment/length partitions. It is pure integer algebra,
not a captured-instruction interpreter. An initial derivative assertion tried
to find both complete constants inside a33byteinstruction pin; that selected
pin ends within the second immediate. The full FDE hash already authenticated
both. The derivative now reads their exact VAs and adds narrow mutation controls.
The original assertion log is retained; production, scope and oracle unchanged.

## Independent expectations and real allocation controls

Before Rust existed, oracle.py froze17980 input/alignment/refusal rows, raw
SHAef831184eb79016f132e9a9c7a45fffde883e7474a1cce7796a0f0378a3e5ffd;
gzip(mtime0)+hex was also stored before source creation. Pure byte-copy/first
zero equations are independent of production. Later128 explicit NUL+refusal
rows were added to qualification after production, preserving original fixture
and source hashes; those additional order controls are NOT pre-Rust frozen.
Total18108rows/profile match actual debug/release with every byte, firstzero,
length/capacity and allocation request count. Input remains unchanged. Probe
also checks normal success/error positions against actual std::ffi::CString,
not against a captured node or native runtime oracle.

The library uses real alloc::Vec/try_reserve_exact. The probe's real System
GlobalAlloc wrapper delegates every successful operation, only returningnull
for a selected actual request during the call. This exercises real allocation
refusal even when input is empty/NUL, not mockVec storage. Seven actual source
mutants compile and are detected: pre-rejection, wrongcapacity, lastzero,
wrongzerobyte, wrongterminator, offbyoneposition and append-on-error. Three
return normally with differences; four fail actual std/assertion controls with
exit101. Neither compiler failure nor unrelated crash is counted as a semantic
normal-output mismatch. Qualification retains exits/hashes, with original
compiler/actual/stderr logs in ignored work. Same-author static interpretation
remains fallible and is not peerreview/native execution proof.

## Physical evidence and limits

Fivecomplete FDEs total1219B/371instructions: primary378B, finalizer225B and
three real filesystem/DB caller contexts. Native GNU/LLVM/Capstone partitions
agree; readelf extents agree;13real instruction anchors+two identity controls
reject, in addition to16constant controls above. Full bodies/unwind/calls/
branches/actualRELAwriters are retained. Contexts include prior-owned research
and receive no new byte-equivalence or private-code credit. Captured binaries,
OS/filesystem/TLS/network callbacks and unlicensed inferred source are never run.

```
source work/environment/new-three-env.sh
python3 -B research/work-items/RE-012-owned-cstring-115/verify.py
python3 -B research/work-items/RE-012-owned-cstring-115/derive.py
python3 -B research/work-items/RE-012-owned-cstring-115/qualify.py work/cstring-fresh
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-owned-cstring/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-owned-cstring/Cargo.toml -- -D warnings
make doctor verify catalogue-check reproduce
```

Actual host/Linuxrlib/fmt/clippy/repository results are in validation.json.
Unchanged583-file base qualification reused explicitly with25skips; no new
full-suite or hostedCI claim. All92 gates and byte totals unchanged. Whole
node/native ABI/allocator/unwind/generic-finalizer and caller integration remain
open. Next: establish command program/argument state construction and its
sticky invalid-NUL behavior using this now-buildable converter dependency.
