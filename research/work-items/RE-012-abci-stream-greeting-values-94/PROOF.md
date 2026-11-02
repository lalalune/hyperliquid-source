# Complete ordinary-return greeting relation

The theorem is CONTRACT.md under its canonical Reader, valid span, allocator,
copy/compare, ordinary-call and frame premises. It is conditional static proof,
not captured execution, source identity, current network compatibility or a
claim that symbols determine semantics. The full 30 FDEs contain 19,082 bytes
and 4,317 decoded rows; the 28 core bodies contain 17,147 bytes. The 89-byte
passed byte-function and full 1,846-byte caller are separately marked context.
No tiny-window inference substitutes for a full body.

`scope.json` binds exact PT_LOAD offsets, FDE/CIE bytes and every call. Native
GNU and LLVM exports independently decode the same complete byte partitions.
`obligations.json` binds every 4,280 non-padding instruction and all seven
dispatch tables, two names and two bound records. `records.json` retains all
call/RIP references, branch successors, register-loaded call proofs and LSDA
metadata. None of these static census checks alone proves the following
semantics; they make the manual premises and addresses reproducible.

## Charge, cursor and scalar relation

The canonical u64 limit tag is essential: DWORD-equals1 tests and QWORD-nonzero
tests agree only in the declared 0/1 domain. No call can mutate it or another
escaped Reader field except the proved Reader operations.

u32 466bc11..bc38 and u64 466bd11..bd38 compare the old charge to MAX-4/MAX-8,
branch on unsigned greater before any charge store, then add/store and compare
to the limit. usize466be70 has the same 8-byte admission. fixed20/32 and the
2048-byte record repeat this order with their respective constants. The raw
signature byte466bb15..bb30 uses an equivalent formulation: exclude old=MAX,
store old+1, then reject old>=limit. For representable old+1,
`old>=limit` iff `old+1>limit`. No charge-failure branch changes the input span.
These are integer equivalences for the complete u64 domain, not sampled tests.

After accepted charge, 466bc3d/bd3d/be9d compare remaining with4/8/8. Strictly
greater selects the fast path. Byte marker0..250 goes directly to a one-byte
commit. Subtract251 followed by unsigned comparison to3 bounds the four-entry
tables. Their signed rel32 destinations are read from6f6e98/ea8/eb8. Supported
251/252/253 load exactly2/4/8 little-endian payload bytes; u32 rejects253.
The fast threshold guarantees every supported payload fits. Invalid arms call
466dac0 before any cursor store, with expected2 for u32/u64 and5 for usize.

The slow calls466bcb0,466bdba,466bf1a pass Reader+0x10 and EDX=0 to complete
466d850/466d980/466dad0. Those leaves first test remaining zero. Otherwise they
load the marker, advance pointer1 and subtract remaining1 before interpreting
it. Supported widths either report missing payload bytes without further
consumption, or load exactly that payload and advance by its width. EDX=0
selects little endian; no other endianness branch is needed for this operation.
Invalid expected codes are2/3/5; found is3 for rejected253,4 for254,12 for255.
466dac0 writes exactly kind3 and the two code bytes. In particular u64 fast
and slow invalid markers have different expected codes and cursor effects.
Neither branch checks minimal encoding. The complete scalar success tag is
0x12; the proved leaves never produce0x13.

Fixed-width reads charge before comparing remaining. A shortage computes
width-remaining and returns kind0 without consuming fixed bytes. Success stores
the new pointer and remaining, copies precisely the fixed span, and returns the
payload. Overlapping output stores in the unaligned layouts reproduce the same
source bytes in the overlap; inactive padding is not interpreted. Byte-span
addition/subtraction cannot wrap in the declared readable nonwrapping span.

## Bulk vector, signature and records

4589a49 reads a u64 length N, then 4589a5e..a8d applies checked charge(N).
The remaining test precedes allocation. Shortage returns kind1, not kind0.
For N=0 it chooses the empty representation without allocation and still calls
memcpy4589af9 with destination sentinel1 and count0. CONTRACT.md expressly
requires that zero-length call to return without dereferencing either pointer.
Otherwise it allocates N bytes and the same call copies exactly N. Only after that successful
copy does it commit Reader cursor/remaining. N>isizeMAX cannot pass the admitted
remaining test. Full-body register use never reads/calls the incoming element
function RDX: outer467486c's pointer466bbb0 is context only, not a per-byte call.

466bf60 reserves32, then stores old+24 before the first u64 call466bfbe, and
refunds8 before calls466c001/c044/c083. Each scalar charges8 back. An accepted
reservation means every later refund is representable: after each successful
scalar total charge is the same reserved sum. If a scalar fails, that sum stays
charged; no group rollback occurs. Disabled mode skips both reservation and
refunds. Scalar0x13 and refund-underflow diagnostic paths cannot arise by this
invariant and the closed scalar result partition; they are not treated as
fabricated noreturn calls. The success block reconstructs the first u64 from
its low byte plus upper56 bits and copies the other three words unchanged.

466ba93 and466bac6 call that group twice in order. The first error short-circuits
the second group and final byte; the second error short-circuits the final byte.
466bb3b..bb4c reads one unrestricted byte after its charge/EOF test. Four16-byte
copies at466bb77..bb83 put the two groups consecutively at result+8..+71; the
raw byte is at+72. The success tag is0; error tag1 carries a separate32-byte
active-error area. Map shuffles copy the64 limb bytes and that byte to a72-byte
inline value; the remaining seven bytes are padding. No recovery-id bound or
signature validity follows from this parser.

466de76 and466de91 read two usize values, then466dea4..dedb charges/checks2048.
On success466df46/df4a commit input2048; stores466df53..df69 cover source0..22
(overlaps preserve the same bytes), and memcpy466df76 copies source23..2047
to result+0x1f. Scalars are at result+0x808/+0x810; after removing the result
tag, one record is0x810 bytes with byte array first, then the two u64 values.
On failure only its active error is exposed; no heap record was allocated.

485bae6,485bb30,485bb75 read exactly three records and short-circuit each error.
Success copies the records into contiguous stack ranges at+0x820,+0x1030,
+0x1840, each0x810 long. They end at+0x2050. Other temporary record ranges
+0x2050,+0x2860,+0x3070 are adjacent, not overlapping; the full stack frame
and its page probes are assumed valid. Allocation485bc28 requests0x1830 only
after all three records succeeded; memcpy485bc46 copies their concatenation.
The returned word is an owning pointer to those records, not a decoded scalar.
The native tag's word-sized observation in earlier work does not prove a u64
logical type. This packet adds that closure without rewriting the prior packet.

## Map decoding and ownership

All three complete readers496ec70/496f030/496f370 read N via466bd10 first.
For the first reader,496ecad multiplies96*N with unsigned overflow detection,
496ecb2 adds the current charge with carry detection, and496ecbc stores the
finite sum before496ecc0 compares the limit. Product/add overflow has no store.
Root/length are initialized empty only after accepted reservation. For each
remaining row496ed30..ed48 refunds96; fixed20 call496ed52 precedes signature
call496ed98, which precedes insertion496eec9. The other two full bodies have
the same operation order and their separate exact bindings are retained.

Let C be the charge after the length scalar. After k complete rows, the charge
is `C + 96*(N-k) + 85*k`. For k<N the unprocessed reserve contains96; refund
cannot underflow. The actual row charges20+32+32+1=85, so accepted reservation
is never exceeded during a row. Thus no hidden limit failure or arithmetic
overflow arises inside a map row after its reservation, though read errors
still occur and retain their partial charge. Error propagation never refunds
the unprocessed reservation. With charging disabled, none of the product,
reserve/refund arithmetic runs; a large N is not a preallocation request.

TREE-PROOF.md proves all three insertion/search clones, the complete3839-byte
split/parent propagation, fresh-root and duplicate-replacement paths and both
cleanup traversals from empty maps. The result is a finite relation whose last
wire occurrence wins. Map length counts distinct keys, while charge counts
all wire rows, including replacements. A successful row consumes at least29
input bytes, bounding distinct count/height and guaranteeing eventual failure
for an overlarge wire count in a finite span. No opaque-map premise hides the
algorithm. Allocation, memcpy/memmove/memcmp and unrelated-memory frames remain
explicit external premises.

Readers496ec70/496f370 clean partial trees through494e540 on ordinary error;
496f030 uses49b5c50. No key or signature owns nested heap state. A failed second
map in49784e0 first returns after its own partial-tree cleanup, then49786db..
87c1 destroys the complete first map. Every active error is copied into a
disjoint result before cleanup; deallocation cannot change the Reader under
the declared frame. No cleanup callback reads or changes the logical values.

## Nested and outer assembly

466e76a reads nested u32 tag. Tests466e77c/e784/e78d distinguish0,1,2; greater
values construct kind5 with `GreetingHash`6f877f and bounds209410. Arm0 charges
and reads32 inline, preserving its bytes across map496ec70 at466e9af. The
unaligned copies466ea4d..ea84 put exactly H[0..32] at+8..+39, then the map
triple at+0x28..+0x3f, returning tag0. Arm1 calls49784e0 at466e81a; that helper
reads fixed32, first map496f370, second map496f030, in that order. Successful
assembly4978612..8666 is H32 at+8, map1 at+0x28, map2 at+0x40, tag0. Nested
assembly copies its80 active payload bytes and changes the nested tag to1.
Arm2 calls485baa0 and returns nested tag2 with the owned record pointer at+8.
Any nested error returns nested tag3 with active error at+8.

467483c reads outer u32 tag. Unsigned compare4674852 bounds the six-entry
dispatch6f700c; tags2/3/4/5 write native4/5/6/7 and return immediately. Tag1
calls466bd10 three times at467496e/498d/49ac, stopping on the first error.
Success46749ca/49ce/49d2 stores b,c,a; the logical API labels wire order a,b,c.
Tag0 calls bulk vector467487b, scalar46748a4, nested46748c3, in that order.
Nested0/1/2 success becomes outer0/1/2, preserving its active payload. Vector
capacity/pointer/length occupy+0x58/+0x60/+0x68 and Q occupies+0x70. Nested
tag3 errors become outer8; later failure frees the separately owned vector
at4674ad7 iff its capacity is nonzero. Invalid outer tags use literal
`AbciStreamGreeting`6f878b and bounds203580. All error arms propagate active
fields only; their wider machine copies do not initialize inactive bytes.

All successful branches return one complete owned logical value; errors expose
no partial map/vector/record value. Reader state always reflects the first
failing primitive and previous successful reads, with no rollback. Operation
order is proved from complete control flow, not from fixture order.

## Selected caller and proof limits

Full471b880 starts with testEDX at471b894. EDX=0 branches directly to471b92b,
skipping all instrumentation/TLS calls. It reads supplied pointer/length/limit
pointer and initializes Reader tag1, charge0 at471b943/951. The only normal call
on this selected branch is greeting471b967. Success computes oldlength minus
remaining at471ba0a; the underflow guard is unreachable because every proved
read consumes at most remaining. The result receives consumed at+0x80 and
Some tag1 at+0x78. Error branch471bad6 forwards the active error and None at
+0x78; +0x80 stays inactive. No trailing-byte exhaustion check occurs and the
supplied caller descriptor is not modified. Other caller branches are retained
context and remain unresolved.

CALL-FRAMES.md separates ordinary core calls, bound diagnostics, cleanup and
excluded unwind/instrumentation. LSDA bytes identify protected calls/landing
pads; they do not prove personality/filter behavior, unwinding correctness or
ordinary-return equivalence after a panic. All external calls must satisfy the
declared ordinary frame even if an input/output pointer escaped earlier.
No claim relies on an opaque call being harmless merely because it lacks an
explicit overlapping store in the inspected caller.

The independent grammar oracle uses mathematical integers and flat dictionaries;
the finite corpus challenges all value/error classes and retained state. A
future source may use a standard ordered map and the merged scalar provider,
but must prove its own bridge. Corpus agreement alone cannot prove the native
premises, all inputs, allocator behavior, a Rust layout or a second independent
target provenance. The capture and its derived packets are one project lineage.
