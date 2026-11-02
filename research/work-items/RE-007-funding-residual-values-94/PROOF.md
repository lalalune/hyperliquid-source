# Supplied-summary residual application: manual proof

This is the manual conditional proof for the pre-code packet. No production
implementation, qualification client or build harness is present. All native
observations bind node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The prospective baseline is main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Read CONTRACT.md and CALL-FRAMES.md as explicit premises of every statement.

## Admitted complete operation

Accept the supplied stream of worker-shaped summaries and an explicit state
snapshot at the completion of the opaque worker bridge. Reconstruct summary
insertion, sorted consumption, sequential saturated residual accumulation,
winner selection, row-prefix flattening, and the complete selected residual
state change. The selected user and asset must already exist whenever a
nonzero residual is applied. That restriction is useful for summaries produced
from existing positions while the corresponding state remains live and stable;
it is an explicit provenance/frame premise, not a fact inferred merely from a
summary's shape.

The operation is not the whole `0x3703f20` entry-to-return state transition:
the worker bridge can change users before the supplied snapshot. Its scheduling,
coverage, return order and worker calculations remain outside this contract.
The supplied stream must have unique 20-byte keys, actual tags 0/1, valid owned
row vectors, and (for a selected tag1 summary) its selected-address payload must
equal its key. The native replacement behavior for duplicate keys is separately
known, but uniqueness is the admitted worker-corresponding domain. No target
prevalidation of these premises is claimed.

Subject to successful ordinary allocator/copy/free/helper calls and the precise
valid-tree, hash-table, lifetime and noninterference premises below, all value
writes/lookups/insertion/flatten paths required on that domain are bounded.
The novelty over merged PR899 is closing previously stubbed state lookup,
address-set insertion and the auxiliary-map effect, plus a real offline value
implementation after independent pre-code qualification. A sum/maximum leaf
alone would not justify a separate contribution.

## Exact recovered value relation

1. Each 104-byte supplied record has key20 at +0 and an 80-byte value at +24.
   The value contains row-vector cap/pointer/length at +0/+8/+16, signed sum at
   +24, tag at +32, asset at +40, unsigned magnitude at +48 and selected address
   at +56. `33c5500 -> 33077d0 -> 33a5e70 -> 2f646d0` consumes the chunk list and
   inserts by unsigned lexicographic key order. Repeated keys would replace the
   entire old value and free its old row allocation; they do not add sums.
2. `3bb1150 -> 33af8e0` destructively walks the resulting tree in key order and
   creates 80-byte rows. On tags0/1 every entry is consumed. Tag2 is a special
   sentinel and is outside the admitted supplied stream.
3. `37040dd..3704131` folds signed sums in this order using saturating i64 add.
   This is not the clamp of an arbitrary-precision total: `[MAX,1,-1]` yields
   `MAX-1`. Overflow diagnostic calls occur before the saturated accumulator
   update. They must return normally and preserve the explicit frame.
4. `3704140..37041b7`, `3704353..37043f2` choose the first tag1 maximum unsigned
   magnitude; a tie does not replace the earlier address. The optimized pair
   loop tests the first row's low tag byte and the second row's full dword,
   whereas the odd tail tests a dword. The 0/1 premise is essential to the
   uniform logical contract. No raw arbitrary-tag equivalence is claimed.
5. `3bafb90` copies opaque 72-byte records in outer address order, stopping each
   inner vector before its first record with little-endian u32 at +60 equal to
   zero, then continuing with the next outer vector. Its front/back iterator
   state is initialized by this caller with no back vector. It frees all owned
   input allocations, including discarded suffixes. It completes before any
   residual debit at `3704209`. Empty rows, all-empty summaries and zero-total
   summaries still follow this flatten rule.
6. If there is no winner or total is zero, no user/ARU/auxiliary-map mutation
   occurs. Otherwise `3596940` returns the selected existing user's active state;
   `339b590` inserts its address into dex+0x188 (ARU) before the position lookup.
   The native position B-tree search and occupied `33bd420` path return the
   existing 64-byte position, without constructing a default.
7. The selected raw position dword at +0 equal to **1** chooses position+8
   margin. Every other raw dword chooses user+0 cross balance. The destination
   becomes `sat_i64_sub(old_destination,total)`. Position size at +16, leverage
   at +4, and user count at +32 are separate fields and stay unchanged under
   disjoint-memory/frame premises.
8. `3704478..3704486` calls `36f7350(asset,size,size,&user_count,&dex_aux_map)`.
   Its count update is exactly inactive for equal sizes, but its map effect is
   not generally inactive. It obtains or inserts the asset entry with default
   zero **before** checking absolute-size representability. For size != MIN,
   set `a=abs(size)` and `x=old entry or 0`. The two ordered stores are
   `y=sat_i64_sub(x,a)`, then `z=sat_i64_add(y,a)`. Thus
   `z=max(x,MIN+a)`. Missing membership becomes present even for size0.
   Example: existing x=MIN,size1 becomes MIN+1; an absent entry,size1 becomes
   present0. If x is separately known nonnegative, the value is unchanged,
   but that does not eliminate missing-key insertion.
9. The equal-size helper does not change user count. The leverage comparison
   also remains equal; its post-debit value is loaded before the auxiliary
   call. Therefore the later leverage-update and users-with-positions update
   calls are not taken under this contract. They are not assumed inert.
10. The native output vector descriptor is stored before the owned rate-map
    drop (`370450d..3704524`). The supplied-summary value API would return the
    flattened records and explicit residual state result; it would not claim
    native allocation layout/capacity/free events or a timing/logging API.

## Necessary helper closure examined

`scope.json` and `records.json` bind 29 complete FDEs:25,803 bytes and5,832
grouped instruction rows. Of these,25 bounded operation/support helpers have
22,771 bytes/5,130 rows; four caller/worker/vacant-constructor contexts have
3,032 bytes/702 rows and do not expand the value contract. GNU and LLVM exports
cover every byte, with LLVM's four isolated LOCK prefix rows grouped with their
following instructions. Both decoders inspect one private digest-bound snapshot.
All5,750 instructions other than decoded NOP padding are compact byte/decode obligations for the
manual proof. Pins are admission evidence, not automatic semantic equivalence.
The two hash-constant spans and every RIP reference/relocation are bound.

The scout also exported vacant-position generic insertion2f24930, but that body
is deliberately absent from the admitted29-function scope. Full3bfffd0 and
3759880 are retained as excluded-constructor contexts. Their further callees are
not claimed closed. The complete cold bytes/LSDA pointers are retained without
claiming ordinary control-flow coverage of exceptions or panic rollback.

| Role | Full FDE | Reason it is needed |
| --- | --- | --- |
| Residual host | 3703f20..3704678 | Full sum/winner/flatten/state ordering and cold paths |
| Supplied-chunk collection | 33c5500..33c56e6 | Linked chunk ownership and record handoff |
| Chunk extension | 33077d0..3307932 | 104-byte stride, replacement and vector frees |
| Summary entry | 33a5e70..33a61c1 | memcmp20 search, occupied replacement and empty root |
| Summary insertion | 2f646d0..2f659f5 | Complete general split cascade and parent/root repair |
| Summary consumption | 3bb1150..3bb1417 | Sorted 80-byte output and tag2 boundary |
| Destructive tree iterator | 33af8e0..33afca1 | Leftmost/right-child/parent traversal and node frees |
| Flatten | 3bafb90..3bb02f2 | Inner prefix semantics, output copies/growth, ownership |
| Iterator/vector cleanup | 3402670..34026fb; 3bbae90..3bbaf14; 3bbb8e0..3bbb9c9 | Ordinary remainder/drop handling |
| Existing user lookup | 3596940..3596b23; 379a390..379a4ce | Occupied entry and exact 20-byte hash-key comparison |
| Seeded key hash | 399c7a0..399c8e5; 3a00700..3a008d7 | Complete fixed20 hashing chain, no additional calls |
| ARU insertion | 339b590..339b7b3; 2f33ac0..2f3446a | Exact memcmp20 set semantics, full split cascade |
| Position entry | 33bd420..33bd611 | Existing-position return; vacant path explicitly excluded |
| Auxiliary update | 36f7350..36f7559 | Count, entry, ordered arithmetic stores and MIN failure |
| Auxiliary entry/insertion | 33bc4d0..33bc5e6; 2f18f20..2f19906 | Existing value or inserted zero; complete general split |
| Vector growth | 32d6a00..32d6a8e; 32d6740..32d682a | Checked capacity/size and allocation outcomes |
| Rate-map cleanup | 33f4660..33f49ad | Node traversal/free after output stores |
| User pointer collection | 3bc9a80..3bc9cb6 | Every occupied slot once under exact valid table count |
| Worker bridge context | 38dc6a0..38dc7d0 | Supplied-stream boundary, not a scheduler theorem |
| Complete caller context | 222bef0..222c646 | Real call slot, immediate returned-record free, premium reset |
| Excluded constructor contexts | 3bfffd0..3c001e6; 3759880..37599bc | Prove that vacant paths require additional scope; not part of the supplied existing-position contract |

The three required split cascades share capacity11 and fully visible insertion
logic, not an opaque abstract-map assumption. For insertion index i in a full
node, the existing pivot is 4 for i<5, 5 for i=5 or6, and6 for i>6; insertion
goes to the left for i<=5, to right index0 for i=6, and right index i-7 for
i>6. Keys and their values move together. Promoted separators propagate upward;
nonfull parents shift suffixes and insert the right child; full parents repeat
the split. Child parent pointers/indices are repaired after every affected
copy/shift, and exhausted parent chains allocate a new root and increment
height. Exact node geometry:

| Tree | keys | values | parent/index/count | children | leaf/internal bytes |
| --- | --- | --- | --- | --- | --- |
| Summary | +378, stride20 | +0, stride80 | +370/+454/+456 | +458 | 458/4b8 |
| ARU | +8, stride20 | unit | +0/+e4/+e6 | +e8 | e8/148 |
| Auxiliary | +8, stride8 | +60, stride8 | +0/+b8/+ba | +c0 | c0/120 |

These hexadecimal layouts plus valid ordering, exact counts, balanced height,
live disjoint storage, nonwrapping bounds and successful allocator/copy frames
support a general insertion induction. No captured node was evaluated.

The occupied user lookup also closes without relying on a lookup stub. The
complete seed-dependent hash leads to h2=(hash>>57), group probing and exact
20-byte equality. The valid SwissTable premise includes seed/hash-consistent
placement, control-byte mirrors, bucket-mask shape, terminating empties, exact
occupied cardinality and unique keys. `3bc9a80` enumerates occupied control bits
once into `(address_pointer,user_pointer)` pairs. This proves the pointer list,
not that the opaque parallel worker visits each pair exactly once or returns
all summaries. That remains a separate supplied-stream provenance premise.

## Caller context and excluded paths

The actual full caller `222bef0..222c646` tests its initial byte==1, constructs
or clones rates, loops paired dex entries, passes the raw input byte/time/rate
map at `222c03a..222c04d`, and calls slot5773a78. Its single RELATIVE relocation
has symbol index0 and addend3703f20. It immediately frees the returned 72-byte
row allocation at `222c053..222c06c`, then traverses tracker+0xd8 and zeros
premium-vector lengths at node value+0x70. Therefore this particular caller
does not expose the returned rows to a record-storage consumer. Whole host
gating, rate construction, scheduler behavior and the timing tail are outside
the operation; they are not silently promoted into the new API.

Vacant user entry would initialize a new user, call the default packed-date
helper and potentially grow/rehash its table (`3596940 -> 379a390 -> 3580600`).
Vacant position entry invokes `3bfffd0`, asset/dex metadata bounds, margin-table
lookup/construction `3759880 -> 3398f50`, owned-table cleanup, and `2f24930`.
Full `3bfffd0` and `3759880` were read to establish this additional scope, but
the entire transitive construction closure is not qualified. Excluding these
paths is part of the explicit existing-position contract, not a claim that
they are unreachable for arbitrary supplied bytes. No full-account default
constructor is proposed.

SizeMIN is excluded from the ordinary-return domain. The native helper may
insert an auxiliary entry and then panic, **after** ARU insertion and residual
debit. A new safe API may reject MissingSelectedUser, MissingSelectedPosition,
SizeMagnitudeOutOfRange, duplicate/provenance-invalid summaries or impossible
spans before mutation; such rejection/atomicity is a new admission policy,
not native failure behavior. It must be documented and frozen separately from
native-corresponding cases. Invalid unused state need not be inspected when
total0/no winner bypasses mutation; the exact source policy should retain that
lazy boundary where possible.

## Frame, length, ownership and interpretation limits

All key/value/child/row spans must be live, aligned as accessed and nonwrapping.
Map fields, original user/position state, row allocations, summary trees, rate
maps and new allocations must be disjoint where writes could interfere. Counts
must reflect actual storage; summary/vector sizes80/104/72 and pair size16 must
fit native checked allocation limits. The corpus includes mathematical safe-count boundaries; the complete native
growth arithmetic is a manual obligation, without claiming physical allocation
or Rust Vec capacity/allocator equality. Imported memcpy/memmove must provide
their exact copy and frame semantics; memcmp need only have unsigned-byte
first-difference sign, not a particular nonzero return integer. The saved
Linux man-pages primary interface reference documents that generic premise;
it does not prove the captured dynamic import implementation.

Allocator, free, Once initialization and diagnostics must return normally and
preserve all unrelated exposed state. ABI register preservation alone is
insufficient: the earlier worker bridge has seen state pointers. No later
opaque call may use an escaped pointer to change the admitted post-worker
snapshot, summary storage, tree shape or key. Ordinary-return proofs exclude
panic/LSDA/unwind behavior, allocation failures and concurrent foreign writes.
The whole owned summary/rate cleanup is a framing/ownership proof obligation,
not permission to treat drop callbacks as arbitrarily harmless.

No economic conservation theorem follows from saturating arithmetic. The old
PR899 description of largest-position size is explicitly an inference;
related same-project PR1544 reports the field as
maximum absolute checked product. Credit that result but do not depend on its
unmerged Rust crate, its tests, or its expected fixtures. The public API should
call the supplied scalar a magnitude, not assign unproved financial units.

## Arithmetic proof for all admitted signed values

For signed addition, the no-overflow branch stores the exact sum. On overflow,
the wrapped result's sign selects MIN or MAX: positive overflow wraps negative,
so `(wrapped>>63) XOR MIN` yields MAX; negative overflow yields MIN. The helper
recomputes addition and CMOVO selects that endpoint. Sequential saturation must
therefore be applied after each address-ordered sum, not once at the end.

For subtraction, the signed-overflow branch chooses MAX when the wrapped result
is negative and MIN when positive (`setns` plus MAX with wrapping endpoint
construction). The recomputed difference and CMOVO select that endpoint. This
applies to both cross/isolated debit and auxiliary subtraction. Diagnostics may
run before a store; their exact preservation premise is essential.

For size s != MIN, a=abs(s) belongs[0,MAX]. Let x belong[MIN,MAX]. Then x-a<=MAX,
so only lower saturation is possible. If x>=MIN+a, y=x-a and y+a=x, with no final
overflow. Otherwise y=MIN and y+a=MIN+a, also in range. Hence the ordered stores
produce z=max(x,MIN+a), for every admitted i64 x and size. Count is unchanged:
either both old/new sizes are zero or both are nonzero, so neither zero-crossing
predicate is true. The unrelated leverage field is not written, and its saved
and reread values are equal under the frame; the later branches are not taken.

`certificates.py` supplements this general case proof with exhaustive width8
arithmetic, i64 threshold examples, and all12 symbolic split gaps for each of
three layouts. Its ordered child tokens and key/value pairs certify that the
stated partition relation retains each identity once. The full native copy,
shift, parent/index repair and root-height instructions provide the induction
step for arbitrary finite valid tree height. This is a mathematical sequence
certificate; it neither executes native instructions nor validates corrupt heaps.

## Static assurance and finite examples

The conservative ordinary CFG treats every call as potentially returning. Nine
nonvacuous dominance obligations bind flatten before user lookup, user before
ARU, ARU before position, position before auxiliary, output stores before rate
drop, auxiliary entry before subtract/MIN handling, and subtract before add.
Separate occupied-entry reachability shows no helper call after the occupied
branch in user/position/auxiliary entry. This does not automatically infer which
branch a runtime input takes; that is established by the value/domain proof.

Every call and RIP reference is exported. The complete register-call inventory
in register-calls.json records every loaded-slot origin, including the rax-to-r13
copy at2f64f10 and diagnostic reload on the sum loop. Its census and source
loads are checked; intervening register preservation is a manual full-body/ABI
argument, not an automatic register evaluator. Direct call/tail targets are mapped
into executable PT_LOAD storage; raw RIP disp32 must agree with the decode.
Relocation slots have unique complete .rela.dyn/.rela.plt entries. RELATIVE must
have symbol index0; imported memcpy/memmove/memcmp bind their actual names.
All80,300 dynamic relocation fields are censused, and their eight-byte spans
must not overlap admitted code or either immutable hash constant. Address-only
LEA records bind the pointer's mapped location, not arbitrary opaque consumer
read extents; those are part of the valid-location/call-frame premise.

Byte-negative controls change real instructions, comparisons, field offsets,
call bindings, split pivots/repair, hash constants, FDEs and RELAs below whole
identity gates; both complete native decoders run on each changed body. These
check the admission boundary. Independent fresh-decoded CFG bypass controls
omit instruction pins and must fail the order predicates themselves. None is
a dynamic behavioral observation or universal semantic mutation theorem.

`corpus.py` freezes independent flat-relation expectations and opaque input IDs;
PROTOCOL.md defines complete state/output comparison. Native-corresponding cases
include raw-mode/debit extremes, zero/no-winner lazy paths, unsigned ties/address
prefixes, nonassociative sum, empty and multilevel input sets, zero row sentinels,
negative auxiliary thresholds and unchanged count/leverage/other-state fields.
Safe-policy cases separately cover duplicates, active absent selected state,
MIN rejection and mathematical count bounds. The finite sample never proves
that arbitrary worker output satisfies the supplied-stream assumptions.

## Prior credit and remaining uncertainty

Merged PR899 (dbstkddl8-create, merged2026-11-01) owns the distributor outline and
summary/sum/winner/flatten observations. Its full body and all six changed paths
were read. It stubs state lookup/insertion/update edges closed here; its captured
evaluator is not imported or run and is not a fixture oracle. CREDITS.json pins
the locally copied author-owned static parsing method and the only two imported
baseline ELF/DWARF parsers. SOURCE-PLAN.md describes a possible dependency-free
actual package; source authoring still requires a separate gate.

Two scout GitHub searches (`residual`, `distribute_funding`) and two direct prior
PR reads are recorded in the research return. The first search missed known899;
absence therefore is not ownership proof. Parent full-body/path intake through
1622 is reused without new search calls. Book insertion PR1615's functions
4302290/432bef0/4471d80/447b7f0/4888840 are excluded. No exclusive assignment or
whole funding operation completion is claimed.

There is one target/project lineage, lalalune/hyperliquid-source/node94. Multiple
decoders, same-project prior packets and independent reviewers do not create
independent native sources. Linux man-pages supplies only a generic memcmp
interface premise. Worker provenance, stable post-worker state, successful
ordinary external frames, and absent-constructor exclusions remain conditional.
No Rust, captured executable, emulator, networked node, benchmark, scheduler,
economic-conservation or live protocol validation is claimed by this packet.
