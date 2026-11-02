# Ordered maps, traversal and ownership

This expands PROOF.md's manual induction. All addresses are node94 virtual
addresses in the29 full bodies; no native instructions or heap were evaluated.
Assume the valid finite tree/hash ownership and external frames in CALL-FRAMES.
The allocator/copy premise does not assume that an insertion helper behaves as
a map. The visible entry, split, repair, traversal and cleanup code establishes
that abstract behavior on the admitted domain.

## Search and entry

Summary33a5e70 reads count+456, then compares the supplied20-byte key against
node+378+20*i at33a5ef0/ef8. It normalizes memcmp's sign with sets/setg/sub,
advances while positive, returns occupied on zero, or descends child+458+8*i
while height>0. A negative result chooses the first greater key's child. At a
leaf this is exactly the insertion gap. No particular nonzero memcmp integer
is required. Occupied33a5f46..fc6 copies all80 old bytes out and all80 new bytes
in, without changing map cardinality. New empty root33a6093..613d allocates458,
sets parent/count0 and height0, copies key20/value80, increments count and map
cardinality, then returns tag2 for no replaced value. Nonempty vacancy delegates
to the complete2f646d0 with that exact gap and increments cardinality once.

ARU339b590 applies the same signed memcmp20 result to keys+8+20*i and count+e6;
children are+e8+8*i. Existing address returns without insertion. Vacancy uses
the full2f33ac0 or an allocatede8 leaf, and increments cardinality exactly once.
Aux36f7350 compares unsigned asset keys at+8+8*i, count+ba, children+c0+8*i;
33bc4d0's occupied path returns node+60+8*i without a helper. A vacancy calls
2f18f20 with value0 or creates ac0 leaf, then increments map cardinality.
These distinct entry predicates are essential: an existing key preserves its
old auxiliary value; an absent key obtains0 before arithmetic.

## Full insertion induction

The invariant for a subtree is a sorted sequence of unique key/value pairs,
with child intervals partitioned by separator keys. Nodes have0..11 active
keys, internal nodes one more active child, correct parent/index backlinks and
one owned allocation each. Inputs are disjoint from shifting/copy destinations
unless the call is explicitly memmove. The new entry lies in the search gap.
All count/stride/height calculations fit their valid allocation and integer
bounds. A finite tree with bounded node storage has height far below u64MAX.

| Operation | Summary | ARU | Auxiliary |
| --- | --- | --- | --- |
| Nonfull leaf admission |2f646e7..2f648d7|2f33ada..2f33b5a|2f18f37..2f18fd9|
| Full leaf pivot cases |2f646fd..2f64723,2f64793..2f647b7,2f648df..2f648fd|2f33b63..2f33bb8|2f18fe7..2f19035|
| Split copies and left truncation |2f64902..2f64a48|2f33bb8..2f33c44|2f19035..2f190e3|
| Internal split and repair |2f64d70..2f653e6|2f33d54..2f340b4|2f191e4..2f19545|
| New root and height |2f65439..2f6553b|2f340c0..2f34160|2f1955d..2f195f9|
| Nonfull parent and suffix repair |2f6557a..2f657cc|2f34168..2f342f7|2f19600..2f197b8|

These ranges are reading guides. Full exact instruction boundaries remain in
native exports and obligations; no function is truncated to a listed guide.

For a nonfull node with n keys and insertion gap i, move the suffix[i,n) one
slot right, copy the new key/value into i, and set count=n+1. Summary shifts
key bytes in20-byte units and values in80-byte units; ARU has no value payload;
auxiliary shifts keys and values in8-byte units. The visible memmove calls and
fixed field stores maintain key/value association. No preexisting key is lost.

For a full11-key node, choose original pivot4 when i<5, pivot5 when i=5 or6,
and pivot6 when i>6. Copy the original suffix after the pivot to a new right
node, save the pivot key/value, truncate the old left node, and insert the new
entry on the left at i for i<=5, on the right at0 for i=6, otherwise right at
i-7. The resulting relation is left + promoted + right, with12 total keys;
left/right have5 or6 each. `certificates.py` checks every one of these12 gaps
using distinct ordered key/value tokens for all three geometries.

For internal nodes, copy the corresponding child suffix with8-byte pointers.
Insert the incoming right child immediately after its left counterpart. Repair
every moved child's parent pointer and index: summary parent+370/index+454,
ARU parent+0/index+e4, auxiliary parent+0/index+b8. Explicit repair stores occur
at2f65002/65274..652f3/65744..657c0;2f33ee2/34014..3408a/34274..342ea;
and2f19392/194b4..1952e/19704..197b1. Tail and four-at-a-time loops cover all
active children. The sequence certificate checks that the13 resulting child
identities partition into left_count+1 and right_count+1 in order, with none
duplicated or omitted. Backlink writes refer to these actual partitions.

The promoted separator and right node propagate to the original parent at the
saved parent index. A nonfull parent terminates this process by the same suffix
shift/insert rule; a full parent repeats the split. Each repetition moves one
level upward in a finite tree. When no parent remains, a fresh internal node
gets the old left child at child0 and the new right child at child1, the promoted
key/value at0, count1, correct backlinks, and replaces root while height rises
by1. The actual root stores are2f6548d/490,2f34109/10c,2f195a6/5a9. Therefore
induction on old height establishes one inserted entry with all unrelated
entries and sorted lookup behavior preserved, under the explicit frame.

The summary helper also branches on promoted tag2. That sentinel path is not
needed for actual0/1 values. Full bytes remain retained, but no arbitrary-tag
map theorem is inferred. Capacity/bounds failure, OOM, panic and LSDA transfers
are outside successful ordinary insertion. They are not assumed harmless or
silently rerouted to return.

## Summary ownership and sorted consumption

33c5500 receives the opaque worker's owned40-byte linked chunks. It takes the
next pointer, clears next.prev at33c5599, saves cap/ptr/len, then frees only the
chunk node at33c55cb. Valid non-sentinel capacity follows the33077d0 call at
33c55fb. The latter advances by104 at330781c, moves key20 and value80 into the
entry helper, and frees a replaced value's72-byte allocation only when present.
Ordinary unique-key input has no replaced value; every nested allocation moves
into the summary tree. The exhausted104-byte backing allocation is freed at
3307907. Early sentinel cleanup is retained but excluded by valid capacities.

3bb1150 creates a consuming tree iterator with exact remaining cardinality.
33af8e0 decrements it once at33af8fb. Initial descent follows child0 to the
leftmost leaf. For a next separator, it records that key's node/height/index
and prepares the next cursor by descending the immediate right child then its
leftmost chain. Exhausted leaves climb via saved parent/index; each dead node
is freed only after its parent and index were read. Thus valid backlinks and
search intervals imply every key/value is yielded once in unsigned address
order. The optimized eight-level descent loops preserve that same child0
composition. Returning no item occurs only at exact exhaustion; invalid
iterator state and premature root exhaustion call failure paths.

The sorted80-byte vector copies each yielded value. Input tags0/1 avoid the
special tag2 termination; owned remainder drops use3402670/3bbae90/3bbb8e0.
These drops inspect only cap/ptr/len ownership and free raw72-byte allocations,
then the80-byte backing allocation. They do not call an element-specific
financial or user-state destructor. The frame excludes aliasing those owned
allocations with surviving user/position/map state.

3bafb90 is entered with an absent back iterator. At each inner front it advances
by72 and reads u32+60. Nonzero copies the complete72 bytes (including the marker);
zero discards the rest of that inner vector, frees that input allocation and
continues to the next80-byte outer value. Its later loop uses the same marker
at3baffa3/3bb00c2. Remaining back-state code is retained in the full FDE but the
caller's absent back-state initialization bounds this invocation. Output growth
passes size72 to32d6a00, which checks required length/capacity arithmetic and
calls32d6740 for alignment/multiplication/reallocation. Valid live capacities,
not just small logical lengths, are required. Successful resize preserves the
live prefix; no output capacity identity with a safe Vec is asserted.

## User lookup, enumeration and final cleanup

399c7a0 plus3a00700 is the complete fixed20-byte seeded hash chain. Its raw
constant vectors at204ec0 and203e70 are bound; all rotations/add/xor/tail loads
are full instruction obligations. The lookup contract requires a table placed
by that same seed/hash relation, not by a guessed hash name or a new hasher.
379a390 uses hash>>57 as control fingerprint, hash&mask as initial group and
quadratic16-byte group steps. Candidate bits compare all20 address bytes before
returning an occupied bucket; matching fingerprints alone are insufficient.
A valid terminating empty and consistent placement establish successful search
for an existing selected address. 3596940's occupied branch3596aa0 returns the
user at bucket-end-60; it does not initialize a date, add a user or grow the map.

3bc9a80's control iterator takes each occupied bit once by trailing-zero count
and bit clearing, moves across16-byte groups and decrements exact cardinality.
It emits address/user pointers with120-byte bucket stride and user offset24.
This closes enumeration only. The opaque worker/scheduler can still have
separate provenance/completeness behavior, which this supplied-summary theorem
does not infer. Its state mutation precedes the contract's snapshot.

After the returned descriptor stores,33f4660 consumes the independent rate
u64/u64 tree. It walks parent/child links and frees c0 leaves/120 internal nodes;
these scalar values have no per-element callback. Ordinary cleanup is therefore
framed to that owned allocation graph. Unwind cleanup call sites are retained
but excluded. The fullcaller222bef0 immediately frees this host's returned72-byte
allocation, then resets separate premium-vector lengths; no later persistence
or external consumer of those records is claimed here.
