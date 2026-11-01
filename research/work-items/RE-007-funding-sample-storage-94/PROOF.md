# Returned funding-record stream to keyed storage, node 94

This is a conditional static proof for the pinned Linux x86-64 ELF in `spec.json`.
Addresses are linked virtual addresses and ranges are half-open. The complete
19 selected FDEs, including diagnostics and landing pads, are retained. No target
program, captured instruction evaluator, or assembly interpreter is run.

## Result and boundary

Let `R` be the finite, valid 24-byte record vector returned to the host at
`0x222b248` by its call at `0x222b243`. A record is three raw little-endian u64
words `(key, tag, payload)`. Let `P` be the prefix before its first `tag == 2`,
or all of `R` if none occurs. At the selected host record-loop exit
`0x222b480`, under the premises below:

* Every record in `P` with `tag & 1 == 0` appends its **unchanged 64 payload bits**
  to the vector for `key` in the sample map at selected tracker `+0xd8`. An absent
  key starts with the empty vector `(capacity=0, pointer=8, length=0)`. Existing
  active elements and other key/value associations are preserved. The order
  for each key is the order in this returned stream.
* Every record in `P` with `tag & 1 == 1` updates the temporary fallback map only
  when the selected dex object's byte `+0x230` is exactly `3`. It inserts an
  absent key or replaces the existing key's raw u64 value. Thus the last selected
  fallback payload for that key in the processed prefix wins. These records do
  not append a sample. When the byte differs, they make neither selected update.
* The sentinel itself and the suffix after it make neither selected update.

The theorem includes **empty maps, existing keys, absent keys in nonfull leaves,
full leaf splits, cascading full internal-node splits, and root growth**. It is
not restricted to an existing-key fast path. It concerns active logical entries;
vacated/inactive slots may retain stale bytes.

For batches actually produced by the selected leaf producer, tags are exactly
0 or 1. A nonexcluded input key yields `(key, 0, returned_word0)` when the
two-word premium helper result has nonzero word1, and `(key, 1, oracle_word)`
when word1 is zero. This relates the producer's result representation to the
host's storage choice without assigning units or a public source enum type.

The scheduler implementations reached through `0x2428260` are **outside** this
proof. We prove the direct leaf, packaging, returned-list concatenation, and
returned-vector consumer, conditional on the stated returned structures. We do
not prove that every input asset is scheduled, that it is scheduled once, that
concurrent work completes, or that a global asset order matches this stream.
The theorem does not establish a funding payment, rate, sampling interval,
economic correctness, public nonce/asset policy, or source-level type identity.

## Precise premises

1. Ordinary x86-64 execution with the ABI preservation used by these bodies;
   mapped readable/writable spans, valid stack frames, no asynchronous mutation
   of live selected inputs, no alias between output/stack buffers and their
   distinct live inputs unless an overlap is explicitly handled by memmove.
   Pointers plus the accessed byte spans do not wrap. No allocation failure,
   diagnostic, panic, trap or unwind is taken on the claimed normal path.
2. Each selected map is a finite rooted B-tree with unique unsigned u64 keys in
   strict order, at most 11 active pairs per node, correct separator/subtree
   ordering, and a common leaf depth equal to the map height. Each internal node
   has `length+1` valid child pointers. Parent pointers and u16 child indices
   agree with those edges; the root's parent is zero. Storage is distinct among
   nodes. The map header is `(root,height,count)`, with count equal to the number
   of active pairs. Incrementing count and, when needed, height does not wrap.
   This theorem **does not derive validity from arbitrary pointer/capacity bytes**.
3. A sample value is a valid three-word vector `(capacity,pointer,length)` with
   `0 <= length <= capacity < 2^63`, capacity times 8 representable within its
   allocation limit, and valid active payload storage. The record vectors use
   the same word layout and element size 24. The capacities and requested totals
   admit the checked growth below. Input record storage, sample payload buffers,
   B-tree nodes, and temporary fallback storage do not alias. The capacity niche
   `2^63` is excluded: it has actual control significance in `0x1a7cc90` and
   `0x251bc70`; ordinary return alone cannot justify treating it as a vector.
4. At the allocator slot `0x576dfd8 -> 0x54c06b0`, a successful requested `n`-byte
   result is fresh, disjoint, writable storage of at least `n` bytes with the
   required alignment (8 for nodes/vectors, 1 for byte copies). At
   `0x576e030 -> 0x54c5620`, successful `(old_pointer,new_size)` reallocation
   yields a suitably aligned span preserving the old active prefix byte for
   byte, may relocate it, and has no effects on other live selected objects.
   These are explicit **callee contracts**, not behavior inferred from names or
   relocation identity. Their implementations are not closed here. The alternate
   aligned slots `0x576e288/0x576e290` are retained but excluded for this selected
   alignment-8, nonzero-allocation path by the lower-wrapper branch proof.
5. For the imported slot `0x576dfe0`, the contract is exact `n`-byte copy from a
   valid readable source to a valid, disjoint writable destination; it preserves
   memory outside the destination. For `0x576e0e0`, the contract is the same
   snapshot-of-source copy with overlap allowed. The import names `memcpy` and
   `memmove` and their ELF symbol/relocation bytes are evidence of bindings, not
   a proof that a runtime implementation satisfies these contracts. Zero-length
   uses require no dereference. Every split copy has disjoint fresh destination;
   every in-node right shift uses the overlap-capable contract.
6. A cleanup request through `0x576e010` returns normally and preserves every
   other live selected allocation/object and ABI-preserved register. The proof
   records request pointer/size; it does not establish actual freeing, allocator
   ownership, memory safety of arbitrary inputs, or lifetime closure.
7. The premium helper at `0x3750ce0`, called through `0x57745a8`, returns two
   initialized result words, with the first required only if word1 is nonzero;
   it preserves the capture, input arrays, excluded set and existing vector
   contents. Its numeric behavior is credited to prior work, not reproved here.
   The selected prelude's cloned/captured structures satisfy their stated bounds;
   in particular `48*N` metadata-row storage and each nested byte-string length
   fit valid allocation/pointer spans without arithmetic wrap. The exclusion
   set has the stated valid finite unsigned-key tree structure.
   Runtime/scheduler helpers return valid finite batch-list structures with
   correct lengths/links, valid ordinary batch vectors, disjoint live storage,
   and preserve the caller's live selected objects. This premise deliberately
   contains no all-asset or ordering/completeness promise.
8. The central theorem ends at the record-loop exit. Extending the stored result
   to a later dex iteration or host return additionally requires all intervening
   metadata cleanup, timing, formatting, reporting and other opaque calls to
   preserve these selected maps/payloads. The temporary map is passed onward and
   later to cleanup; its continued lifetime or later reported interpretation is
   not claimed. A merely normal helper return is insufficient for this frame
   premise. `native/transfers.tsv` lists every call and tail transfer, including
   the opaque host tail and all exceptional paths.

## Host selection and capture

`0x222af51..0x222af5d` admits only entry byte `[RDI+0x20]==1`; other values return
without this work. The two input vector lengths are compared at `0x222afbc` and
the mismatch call is opaque. `0x222afec..0x222aff6` selects their unsigned minimum.
The selected dex/tracker strides are `0x2f0` and `0x138`. This is a bounded paired
loop, not proof of a global registry's completeness.

The capture constructed at `0x222b1ea..0x222b238` is five pointers:

| Capture offset | Observed pointer and downstream use |
| --- | --- |
| 0 | dex+0x270, unsigned-key exclusion set header |
| 8 | tracker, vector of 0xd8-byte rows used by producer |
| 0x10 | tracker+0x48, first argument to the premium helper |
| 0x18 | dex+0x60, vector of 0x60-byte rows; producer loads row's first u64 |
| 0x20 | local cloned metadata object, forwarded to the premium helper |

`0x254e820` clones the selected 0x30-byte metadata rows. On the valid-count slice
it requests `48*N` bytes, separately copies each row's byte-string of length
`row+0x10`, copies the row's 16 bytes at `+0x18`, u16 at `+0x28` and byte `+0x2a`,
and returns a vector triple. Padding is not claimed initialized. This body was
already studied in `RE-007-liquidate-path-94`; it is retained as a dependency.
The optional set clone `0x289bfb0` remains opaque. The host's extra byte clone at
`0x222b0ff` uses the explicit copy/frame contract above.

`0x24c2180` receives `(metadata_pointer,start,end)`. The host supplies start=0
and end=cloned metadata count. It allocates `8*max(end-start,0)` after size checks.
At `0x24c2210..0x24c2234`, each stored key is `10000*metadata[0x30] + start+i`,
with checked unsigned multiplication and final addition on the admitted interval.
This identifies the produced list; it does not prove a policy bound `end<=10000`.
Such a bound is needed to identify the producer's remainder with `i` in this
caller, and is left as an additional premise, not an observed global invariant.

## Producer and returned-list bridge

The producer `0x251c420` takes output, u64 input slice and state
`(capacity,pointer,length,capture)`. Its exclusion search uses keys at node+8,
u16 length at +0x62 and children at +0x68, under the same well-formed unsigned-key
ordering premise. `CMP; SETA; SBB` yields byte 1 / 0 / 255 for greater / equal /
less. Equality skips the input (`0x251c4f5 -> 0x251c49d`). A failed leaf search
continues to sample construction, rather than rejecting the asset.

At `0x251c510..0x251c532`, let `m=0x346dc5d63886594b`. The full unsigned product
followed by high-word shift 11 computes `floor(key*m/2^75)`; then the code
subtracts 10000 times that quotient. Here `10000*m=2^75+432` and
`(2^64-1)*432 < 2^75`. For every u64 key, the reciprocal error is nonnegative
and less than `1/10000`; adding it to a fraction whose remainder is at most
`9999/10000` cannot cross an integer. Thus the quotient is exactly
`floor(key/10000)` and the index is `key % 10000`, in 0..9999. This arithmetic
fact does not establish that either captured vector has that many entries.

Both row bounds are checked at `0x251c539` and `0x251c54f`. Their failures invoke
the observed diagnostics and trap/exception paths. On valid bounds, the producer
loads the first u64 of the index's 0x60-byte oracle row and passes the 0xd8-byte
row address and the capture to `0x3750ce0` at `0x251c586`.
`XOR EBX,EBX` at `0x251c58c` followed by a byte assignment ensures the later
full-word tag store is exactly 0 or 1, even after the ABI-preserving grow call.
The zero/nonzero test is on the **entire result word1**, not a low byte.
The tag-1 branch copies the original oracle u64 without conversion; the tag-0
branch copies result word0 by `MOVSD`, preserving all 64 bits, including NaN
encodings if the helper supplies them. Stores at `0x251c470/474/47f` write the
three fields at offsets 0/8/16; the length then increments. Excluded inputs
produce no record. The output's fourth word forwards the capture pointer.

`0x255d7d0` zeros the input vector length, checks original length<=capacity,
obtains an opaque runtime split budget, then calls `0x228f410`. In that body,
`(logical_count>>1)<minimum` or the nonstolen zero-budget arm takes the direct
leaf: it builds `(0,8,0,capture)`, calls the producer at `0x228f478`, and packages
it at `0x228f483`. `0x24c2520` produces an empty list for zero length, otherwise
allocates a 0x28-byte list node containing `(cap,ptr,len,next=0,prev=0)` and
returns `(first=node,last=node,node_count=1)`.

The split path computes two sub-slices and calls `0x2428260` with two closure
descriptors. That selector invokes `0x23fade0`, `0x2419d80`, or `0x2423600` under
runtime conditions. Their bodies, closure dispatch, work stealing and completion
are unresolved. Given two valid returned lists, `0x228f57f/583` joins left tail
to right head and fixes the backward edge; `0x228f587` adds node counts. Either
empty-list arm returns the other list, with observed cleanup requests for a
noncanonical leftover chain. No input-to-global-list equality is inferred.

`0x251bc70` consumes the returned list. Its first pass sums batch lengths with
an unsigned-carry diagnostic and a node-count bound. The second pass follows
`next` until null, saving it before each node disposal and clearing next.prev.
It copies `24*batch_length` bytes into the flat result at its old length and
increments length by that batch length (`0x251bdd9..0x251be09`). Individual
reserve checks remain even after the preliminary sum. It requests disposal of
each 0x28-byte node and, for nonzero capacity, `24*capacity` bytes of batch
storage. Therefore, on the ordinary-vector premise, the result is the exact
concatenation in **returned link order**, including original record bits.
`NEG capacity; JO` at `0x251bdc0/3` treats capacity `2^63` specially and stops
concatenating while requesting cleanup of the remainder; that value is outside
the central admitted domain. No hidden error record semantics are assigned.

## Host lookup, append, and replacement

The result pointer/length are loaded at `0x222b250..0x222b279`; zero length skips
the loop. Tag==2 is tested first at `0x222b2b4`. Only after it fails does
`TEST AL,1` select the two update arms. In particular arbitrary even tags other
than 2 take the append arm; the selected producer's stronger 0/1 range is a
separate result. The fallback byte check is exactly `+0x230 == 3`, without
claiming a recovered enum name.

Sample nodes have keys at +8, 24-byte vector values at +0x60, u16 parent index
at +0x168, u16 length at +0x16a and internal children at +0x170. Their leaf and
internal allocation sizes are 0x170 and 0x1d0. Search compares unsigned keys by
the three-way byte sequence at `0x222b338..0x222b358`; node exhaustion chooses
edge=length, and a failed leaf search constructs a vacant descriptor of height
zero. On equality, the running negative 24-byte offset produces exactly
`node+0x60+24*index` at `0x222b390..0x222b393`.

For a missing key, the host passes an empty vector to `0x287a610`. Its null-node
arm creates a leaf, sets map root and height=0, stores the first key/vector and
sets leaf length=1. Its nonnull arm passes the vacant `(node,height=0,index)` to
`0x1a7cc90`. Both increment map count once at `0x287a6e7`, and return the actual
value-bearing node/index. The host derives `node+0x60+24*index`, tests capacity
against length, grows when equal, writes exactly one u64 at old length, then
increments length at `0x222b295/29c`. No numeric transform intervenes.

Fallback nodes instead have 8-byte values at +0x60, parent index +0xb8, length
+0xba, children +0xc0, leaf size 0xc0 and internal size 0x120. `0x2851610` uses
the same unsigned search. Equality at `0x2851687..0x285168c` replaces exactly
one value and returns its previous word; the host ignores that return. A null
root is initialized directly, and a nonempty vacant leaf calls `0x1a89610`.
Count increments once only on insertion (`0x28516f6`), not on replacement.

## Complete missing-key insertion induction

The two helpers have separate complete native bodies, not a name-based generic
equivalence assumption. They share the following checked arithmetic structure,
with value stride `w=24` for samples and `w=8` for fallback values.

For a nonfull node of length `n<11` and vacant index `i in 0..n`, the helpers
shift `8*(n-i)` key bytes from key i to i+1, and `w*(n-i)` value bytes from value
i to i+1, then write the new pair at i and set length n+1. At end insertion the
copies are skipped. The sample sequence is `0x1a7cce3..0x1a7cdc9`; the fallback
sequence is `0x1a89639..0x1a896bd`. The memmove contracts preserve the suffix
even when source/destination overlap. Thus all old pairs remain in order with
the new pair inserted at exactly i.

For a full node (well-formed premise makes its length **exactly** 11, not merely
>=11), native compare/flag arms choose a pivot old index p and destination:

| Original insertion index i | Old pivot p | Destination | New local index j |
| --- | --- | --- | --- |
| 0..4 | 4 | old/left node | i |
| 5 | 5 | old/left node | 5 |
| 6 | 5 | fresh/right node | 0 |
| 7..11 | 6 | fresh/right node | i-7 |

The sample leaf choice is `0x1a7ccc6`, `0x1a7cd11`, `0x1a7ce19..2e`; fallback
leaf choice is `0x1a896d3..0x1a89727`. The independent parent choices are
`0x1a7d190/2d0..310` and `0x1a89901..960`. The zero/nonzero destination byte
controls CMOVE; only its byte is tested where upper register bits are inactive.

Each split saves old pair p for promotion; sets right length to `11-p-1`; copies
old keys p+1..10 with byte count `8*(10-p)` and their values with `w*(10-p)`;
then sets old length p. The saved pair is removed from both active child ranges.
The fresh node is disjoint, so memcpy is appropriate. The original incoming
pair is inserted in the selected child by the nonfull shift/store operation.
The new pair is **not the promoted old pivot**. The resulting children have
sizes (5,6) or (6,5), and concatenating left, promoted pair, right equals the
original eleven-pair sequence with the incoming pair inserted at i. Strict
separator ordering follows from the vacant-index premise. `consequences.py`
checks this finite 12-position identity independently by list insertion.

For internal nodes, the split additionally copies exactly `right_length+1`
old child pointers beginning at old edge p+1 into the fresh node's edge 0.
It rewrites each moved child's parent and u16 index, including the final edge
(`0x1a7d416..466`, `0x1a89a4c..a96`). Inserting the incoming promoted pair at
j shifts old edges j+1..n right by one and stores its right child at edge j+1.
All children from that edge through the new final edge get parent/index updates.
The remainder loop and four-way unrolled loop together cover that interval
exactly (`0x1a7d1f9..2ae`, `0x1a7d589..641`, `0x1a89b81..c2e`,
`0x1a89dc2..eaf`). Earlier edges retain their already-correct indices. The left
child at j remains in place. This proves the separator/child association as
well as the pair list; merely checking a pivot table would not suffice.

At each iteration, the upward pending object is the old node, saved pivot pair,
fresh right node and current height. The old node's parent/index chooses the
next insertion point. A nonfull parent absorbs this pending pair and terminates.
A full parent repeats the split above, increases current height and ascends one
parent. Finite acyclic parent links and the common-height premise give induction
to the root; the native height-equality checks must pass in this domain.

At a null parent, the helper obtains the actual map header through its saved
entry descriptor, allocates a fresh internal root, installs the old root at
edge0, increments header height, and changes the old root's parent/index to
(newroot,0). It stores the pending pivot at root pair0, the fresh right node at
edge1, root length1, and right child's parent/index=(newroot,1). Sample sequence
`0x1a7d6bc..0x1a7d78d`; fallback `0x1a89c35..0x1a89cea`. This preserves all
active pairs and increases every leaf depth by exactly one. Header count is
updated by the adapters, not these root-growth stores.

The sample helper encodes no pending split with capacity word `2^63`
(`0x1a7cddd..0x1a7ce01`, `0x1a7d2ae..2c7`, `0x1a7d65b..670`). Since all active
sample vector capacities are below that value, every actual saved pivot is
distinguishable from the marker. Arbitrary u64 fallback values use control flow
instead of this vector niche. The sample helper saves the selected leaf handle
at `0x1a7d030..40` before parent propagation and returns it at `0x1a7d78d..7b4`;
fallback saves/returns its corresponding handle at `0x1a897f0/0x1a89806` and
`0x1a89e18..32`. Parent/root changes never move the selected leaf's allocation,
so the host appends to the inserted empty vector, not to a promoted old value.

## Allocation wrappers and copy/frame obligations

`0x32d5780` and `0x454e460` grow sample and record vectors. Their raw candidate
is `max(4, 2*old_capacity modulo 2^64)`; this is not unconditionally a mathematical
doubling. In the admitted capacity domain (including the checked byte-size
limits), doubling does not wrap. Each calls its complete lower wrapper with
alignment 8 and element size 8 or 24, respectively. `0x251b070` additionally
checks `length+additional` carry and chooses max(doubled capacity, needed,4)
for selected element size24, then calls `0x251aec0`.

All three lower wrappers compute padded element stride `(align+size-1)&-align`,
multiply by requested capacity using full-product overflow, and reject when
the product exceeds `2^63-align`. For selected align=8 the stride is 8 or24.
Nonzero new allocations have size>=8, so the branch goes to `0x576dfd8`; nonzero
old capacity goes to `0x576e030`. The alternate aligned slots are structurally
retained but not needed for this path. A nonzero pointer stores success tag0,
pointer and byte size; null stores error tag1. Upper wrappers test the low
result discriminant dword against1 and invoke the diagnostic on failure; on
success they replace vector pointer/capacity while leaving length unchanged.
The exact prefix-preservation and fresh-allocation contracts stated above are
necessary to conclude preservation of existing samples. No allocator body is
silently assumed from a familiar function name.

Register-indirect calls have manually traced slot provenance:

| Complete body | Register call sites | Slot / role |
| --- | --- | --- |
| sample insert | 1a7ceeb,1a7cf08,1a7d3c6,1a7d3e5 | 576dfe0 / disjoint split copies |
| sample insert | 1a7cf64,1a7cf9d,1a7d164 | 576e0e0 / in-node shifts |
| fallback insert | 1a897bd,1a897d1,1a89a01,1a89a1d | 576dfe0 / disjoint split copies |
| fallback insert | 1a8982e,1a8985b,1a89ae7,1a89b01,1a89b3c,1a89d3e | 576e0e0 / in-node shifts |
| recursive bridge | 228f5ba,228f5ed | 576e010 / cleanup requests |
| flatten | 251bdbb,251be2a,251be7a,251beab | 576e010 / cleanup requests |

Other direct-slot calls, all relative bindings including symbol-index-zero,
import symbol records, and opaque host-tail calls are retained in the native
tables. Normal cleanup request lengths are 8*capacity for sample buffers,
24*capacity for record buffers, node sizes above, and 0x28 for batch links.
Exception cleanup has different live-value states and is not promoted into
the normal theorem.

## Structural and exceptional limits

`native/cfg.tsv` covers every decoded instruction in every selected FDE, including
diagnostic and landing-pad blocks. Direct relative branches are decoded from
opcode/displacement bytes, and local targets must be instruction boundaries.
Register calls remain explicit unresolved structural calls; the table above
provides the narrowly audited provenance, not a transitive callee proof.
No selected computed local jump dispatch was found. Calls have conditional
normal-return successors in this structural census, even for diagnostics. It
does not infer that a failure helper returns or that every displayed block is
reachable. LSDA call-site ranges and landing addresses are retained separately;
type/action tables and unwinder behavior are not interpreted.

Leaf size>=12, bad heights, impossible child-copy counts, null allocations,
unsigned arithmetic failures and bounds failures reach retained diagnostics,
traps or exception paths. Those bytes are included and bound; no rollback,
exception safety, resource lifetime, or malformed-input behavior is claimed.
Ordinary storage claims require the explicit valid-entry and helper premises.

## Credit, novelty and downstream use

Seven retained diagnostic Location records bind the producer's row bound to
`l1/src/books.rs:14:16`, its oracle bound to
`l1/src/clearinghouse/oracle/oracle.rs:202:18`, asset arithmetic to
`l1/src/asset/pdi.rs:30:14`, the two insertion checks to Rust B-tree
`node.rs:1027:9` and `node.rs:1876:5`, the flat count to
`core/src/iter/traits/accum.rs:204:1`, and the outer drain check to
`rayon-1.10.0/src/vec.rs:197:9`. Their file bytes contain a zero pointer slot;
the actual source-path address comes from the required symbol-free RELATIVE
relocation, followed by the retained length and u32 line/column fields. These
are literal provenance, not proof of a source type, source licensing, or opaque
callee behavior. No external source implementation is copied.

`RE-007-funding-premium-rate-94` (#860) supplies prior premium/rate/tracker-field
context. `RE-007-distribute-funding-94` (#899) separately studies distribution
and clearing sample lengths. `RE-001-funding-bucket-advance-94` (#116) identifies
the host call; `RE-004-funding-config-writers-94` (#1165) concerns config writers.
The impact walk in #1422 remains separately credited context, not a dependency
for this verifier. None is recounted as this packet's new semantic coverage.

The 2026-11-02 intake through #1466 includes full new changed paths. #1427,
#1449 and #1460 concern reserve adjustment, reserve reweight and row/default
selection at other addresses. #1438 and #1457 study selected portions of another
generic insertion monomorphization at `0x1ab3d20`; their source lineage is not an
independent authority and is credited as related context. This packet proves
the complete selected sample/fallback insertion bodies and their actual funding
consumer. Search absence is not the novelty basis.

A future implementation can use this contract to build a testable raw-record
consumer: preserve per-key append order, create absent sample vectors, retain
last fallback payload, apply the exact sentinel and byte3 guard, and keep the
scheduler boundary explicit. The proof closes a producer-result-to-storage gap
without fabricating the premium formula, global scheduling, or downstream
payment semantics. No Rust implementation or component acceptance gate is
claimed here.
