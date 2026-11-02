# Conditional transaction join value and ownership contract

Target: node94 SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Addresses are original ELF virtual addresses. `scope.json`
binds 12 complete FDEs and their raw FDE/CIE records. Nine bounded core/helper
bodies cover 2,580 bytes / 634 grouped native rows; three caller-context bodies
cover 51,145 bytes / 8,727 rows. The latter are fully decoded to admit the local
call sites, not fully semantically reconstructed. GNU and LLVM byte boundaries
agree, including LLVM's separate LOCK token grouped with its following row.
`obligations.json` pins all 622 non-padding core/helper instructions and the
complete 156-byte error-drop dispatch table. It does not turn this manual proof
into an automatic equivalence theorem.

## Domain and externally supplied contracts

This theorem concerns ordinary return from `4548050..454859e`. The input object,
output object, stack, hash slice, map nodes, live Arc headers/payloads and any new
allocation have valid, appropriately aligned/nonwrapping spans. Output/stack/new
storage are disjoint from all still-live input/map storage. All reads/writes are
ordinary memory. The input block and optional supplied rows are owned references
transferred to this operation. The map retains an owner of every value Arc.
Every successive clone increment, including all occurrences of aliased/repeated
values, starts and ends with a positive signed 64-bit strong count; thus the
LOCK INC / JLE branch at `45482ac..45482b0` is not taken. Count-field writes are
disjoint from the stable hash/map key/value-pointer/time and output storage.
Counts also remain valid throughout cleanup. This is a conservative normal-reference domain, not an exact
reconstruction of the overflow/abort boundary.

The hash pointer/count, raw time, map root/height, nodes, keys and value pointers
stay unchanged throughout the call, including across opaque calls and through
previously escaped or foreign pointers. ABI preservation alone is insufficient.
In particular, the count reload at `454810f` equals the original count at
`45480b1`, and the value reload at `45482b6` equals the value cloned at `45482a4`.
No concurrent mutation or allocator/destructor callback modifies these objects,
the output or caller frame. A block/proof destructor is allowed to free its owned
storage on last-reference cleanup; arbitrary externally observable destructor
effects, alias-observation of partially written output and unwind behavior are
outside the projection. We compare post-return values and safe shared ownership.

For nonempty lookup, the map is a valid finite ordered tree: each node has at
most 11 strictly ordered unique 32-byte keys, corresponding values, and when
height is positive the selected child exists at height minus one. Key arrays,
value slots and child slots have their full live aligned nonwrapping spans. Child key
intervals are disjoint and bounded by adjacent parent keys; all keys are globally
unique. Correct height and acyclic live children terminate descent. These are
input invariants, not checks performed here. Malformed raw nodes, duplicate map
keys, constructor identity and native/std B-tree shape equivalence are excluded.

Imported `memcmp` at slot `576e488` is dynamically bound by type6 RELA, symbol12,
zero addend, name `memcmp`. Assume it reads exactly the valid requested 32-byte
regions and returns a 32-bit signed value whose negative/zero/positive sign is
the unsigned-byte lexicographic comparison, with equality iff all bytes equal.
Its frame preserves all other live objects. The generic sign/equality interface
is documented by [Linux man-pages memcmp(3)](https://man7.org/linux/man-pages/man3/memcmp.3.html),
version6.19 dated2026-08-10. That documentation does not establish the captured
shared-library implementation or its frame; the latter remain premises. The
exact nonzero return magnitude is immaterial. Two failed OpenGroup accesses are
retained in `research-history.json`, not counted as supporting sources.

Allocator slot `576dfd8` points to `54c06b0..54c0772`; deallocator slot `576e010`
points to `54c8cb0..54c8d55`. Their complete exported entries use TLS and tail to
`54be8f0` / `54c7550`. We require successful fresh writable allocation of the
requested positive size, ordinary deallocation of the specified owned storage,
normal return and preservation of unrelated live objects. We do not prove TLS
allocator internals, allocation failure, exact source/native allocation traces or
heap addresses. No opaque callee is assumed noreturn from its label; CFG calls
may return, and explicit UD2 is a sink. LSDA values and exceptional bytes are
retained, but LSDA edges and exceptional semantics are not claimed.

## Value result and lazy access

At `4548061/4548069`, input `RSI+0` is the opaque block/proof Arc and `RSI+8` is
the optional rows Arc (zero absent). The input's 12 raw time bytes are at +16.
No time validity, block layout beyond the hash view, proof validity, signature,
transaction-body hash or row/hash agreement is checked by this operation.

If rows are present, `4548074` falls through to `4548076..45480b0`. It transfers
the exact same block and rows pointers, plus all 12 time bytes. There are no
calls, reference increments, map reads or block hash-metadata reads. The active
success result is raw tag `800000000000002a`, block at out+8, rows at out+16 and
time at out+24..35. Out+36..39 is inactive padding. Thus an empty supplied rows
object, unrelated rows, repeats or mismatched hashes are still passed through.
Unused invalid raw map/hash views need not be readable on this path; safe source
uses deferred checked providers, never invalid Rust references.

If rows are absent, `45480b1..45480c3` obtains `n = blockArc+32` and checks
`n <= 0333333333333333`, exactly `floor((2^63-1)/40)`. For admitted n>0, `45480ee`
and `45480f6` form 8n and 40n; no signed size overflow is possible. The hash span
is 32n bytes; its end pointer must also not wrap. The initial allocation is made
before map/root access. Capacity is n, buffer is the returned pointer, length is
zero at `4548114..454811e`. Successful native allocation is a theorem premise.
The safe source's checked bound and fallible reservation are explicit policies;
refusing there is not a recovered ordinary native error result.

For n=0, `4548304..4548322` sets cap0, non-dereferenced dangling pointer8, len0,
then goes directly to creation of a new empty rows Arc. It does not load the hash
pointer, root or height and does not compare keys. The new empty rows identity
differs from the supplied-empty pass-through, although both contain zero rows.

## Ordered lookup and successful append

With n>0, `4548133` loads hashes at blockArc+24 and `4548138/454815c` loads root
and height at map-argument+32/+40. Null root jumps to first-hash missing with an
empty prefix (`4548333..4548344`). Otherwise `454814d..4548160` saves end/root/
height. Each outer iteration starts at `45481b5`, stages the current exact hash
in stack+64..95, saves its successor pointer and resets root/height.

At a node, `45481f4` loads the u16 key count at +450 (`1c2`). The loop starts
offset0/index-1. `4548210..4548241` compares the query with each 32-byte key at
node+32i. `CDQE; TEST; SETS; SETG; SUB` reduces the result to -1/0/+1; the sign
of the original return is sufficient. The index increments once per comparison.
Strictly greater continues; equality reaches `4548270`; less selects the current
index. Exhaustion selects count via `4548250`. At `4548253`, subtracting one from
height borrows exactly when the old height was zero. Borrow is a missing result;
otherwise `454825d` selects child at node+456+8i and repeats at height-1.

Ordered interval invariants imply by induction on finite height that this finds
the unique map value for an equal key at any level or reports absence. This
proof covers arbitrary admitted finite height; fixtures do not claim to cover
all raw tree shapes. There is no scan-order, comparison-count or memory-layout
equivalence claim for the future std BTreeMap implementation.

On equality, `4548270..454829f` constructs a temporary raw error with tag
`800000000000001c` and calls `453ea10..453ea9b`. The full helper first uses the
negative tag XOR high bit, decrements it, and bounds the resulting index by38.
For this tag the index is27. All39 signed i32 entries at `6f5ac0` are retained;
entry27 targets `453ea99`, whose complete tail is POP RBX; RET. This selected
call performs no payload read or nested call. Other tag arms are not assumed
inert. The helper's push/pop have only the declared private stack effects.

`45482a4` loads value at node+360+8i; `45482ac` increments its strong count;
`45482b6` reloads that same stable pointer. The exact requested hash and shared
value pointer are staged at stack+96..135. `4548170..454819a` writes a 40-byte
row: requested hash32 then Arc pointer8, and increases length by one. Hash order
and every repeated key are preserved. Distinct keys can share a value object;
equal byte vectors can also belong to distinct value objects. No value bytes are
read or hashed by this operation.

Loop invariant before append i: cap=n, len=i, 0<=i<n, and rows[0..i] are the exact
first i request/value pairs. Therefore `45482df..45482e9` always takes the not-equal
capacity branch: the growth call at `45482f4` is unreachable under the stable
count/span domain. This conclusion follows from induction, not old fixture
coverage. The full growth entry `454e3f0..454e454` is exported and its `454f420`
callee remains outside closure because it is unreachable here. After n appends,
the saved successor equals end and `45481af` reaches normal success.

## First missing result and all cleanup conditions

Let k be the first missing request index. All earlier iterations succeeded;
no later request is inspected. `4548347..454838b` writes raw error tag
`800000000000001c` and all 32 bytes of exactly hashes[k] to out+8..39. It does so
before releasing the prefix, row storage and block. No partial rows are returned.

When k=0, `4548392` skips the prefix loop. When k>0, `4548394` starts at rowbase+72,
`4548398` sets counter=k-1, and `[r13-40]` at `45483ba` is the first row's Arc
field at rowbase+32. Each iteration decrements that value. Pointer advances40;
adding -1 to the unsigned counter exits on no carry, so exactly k fields are
processed in original row order (k=1 exits after the first decrement). A zero
strong-count branch at `45483c2` calls the pointer loaded from slot `5773008`,
bound to `4760f80..4760fb9`. The retained full slow-drop helper would free the
byte vector if capacity is nonzero, release weak ownership, and possibly free
the 40-byte Arc allocation. On the declared stable map-owner domain, each
successful clone has a still-live map owner, so these prefix decrements cannot
reach zero, including repeated/aliased values. No arbitrary transaction Drop
semantics are needed for ordinary missing cleanup.

`45483cd..45483e6` frees row allocation iff capacity is nonzero (cap=n>0 for every
ordinary missing result), then `45483ec..4548408` releases the owned block Arc.
If the block still has owners, it returns directly; otherwise slot `57730a8`
calls `4761900..4761967`. That complete helper requests destruction of the block
payload at +16 via `473a300`, optional payload at +264 if its discriminant is not
the signed minimum (CMP zero followed by JO), optional 96-byte records using
count at +512/pointer+520, then weak release/deallocation of size592. These are
ownership requests, not a reconstruction of `473a300` or arbitrary block/proof
destructor effects. The frame/ordinary-return premise above supplies that boundary.

The missing output may be written before these cleanup requests, while safe
source constructs a returned error after dropping temporary values. The theorem
excludes alias-observation during cleanup and destructor side effects; it does
not claim equality of that external event ordering. Safe post-return reference
sharing and ownership release can still be measured without inventing native
refcount values or allocator layouts.

The remaining main bytes `45484da..454859e` retain exceptional landing-pad-style
cleanup, row helper calls and `_Unwind_Resume`; they are not reachable from the
ordinary entry CFG with calls treated as returning. Full helpers `45315f0` and
`4533940` retain their own normal/exceptional row cleanup conditions. No statement
is made about LSDA which-call-to-landing-pad routing or panic/unwind equivalence.
Allocation error paths reach explicit UD2 after their calls if those calls return.

## Fresh result and safe implementation boundary

After zero or n successful appends, `4548420..4548460` stages block plus cap,
pointer and length; initializes row-Arc strong/weak counts1; and requests40 bytes.
Under allocation success, `454846b..45484a4` copies the row-Arc fields and the
original block/time to output. `45484a8..45484b9` stores the same success tag2a
and returns. No block/proof payload is rebuilt. The source can use generic Arc<B>
to preserve the opaque block, actual Arc byte values and BTreeMap lookup, without
claiming these source layouts/allocators match native storage.

Caller contexts are the full FDEs `439baf0..439ec8d`, `4759970..47604b0`,
`4b3c880..4b3f36c`, containing calls `439d9e5`, `475a2e7`, `4b3e257`. Their local
setup supplies state map views at +304/+296/+296 and stack32-byte items. Local
preceding QC-round checks exist, so this packet does not assert that join precedes
every client validation. Whole poll-state/connection lifetimes, decoding, remote
outbox transport, QC validity and batch admission are separate unresolved tasks.

The historical MIT evidence packet `RE-008-client-block-batch-94` / merged PR999
already observed join ordering/cloning/missing behavior and explicitly lacked
Rust. It used bounded native-evaluator fixtures; those were not executed here.
The new contribution closes a full conditional join proof and an independently
authored safe value implementation only after its separate source gate. Native
evidence, project reviewers and disassemblers share one target/project lineage;
none is an independent captured execution oracle. Component gates remain false.
