# Node94 fixed32/two-map caller: manual relation before any checker

Target: node94 Linux x86-64 ELF, 91774280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Reviewed upstream base e5c9b6436876b2a4a39daef813171f9879317699.
Task RE-005 / transport serialization. This is provisional static research.
No captured execution, instruction evaluation, recovered Rust/ABI, or gate credit.

## Distinct question and ownership

Close caller 0x1f646e0..0x1f64973: fixed32, first map, second map,
joint budget admission, exact active output, and cleanup on later failure.
The two map clones and fixed32 primitive are credited dependencies, not new
standalone recovery claims. Own PR1779 already closes the single-map small-limit
relation, PR1742 the paired value, peer1535 the fixed20/fixed32 family.
Canonical current-base research/docs have no focused address hits.
A complete, non-atomic five-page inventory of 472 open PR bodies has no
1f646e0/28916c0/2890ea0/28570c0/285c600 match. Recheck before publication.

Evidence: node94-selector0-helper-intake-20261102T051627Z.json,
node94-greeting-nested-maps-intake-20261102T065431Z.json,
node94-nested-map-dependencies-intake-20261102T073533Z.json,
node94-nested-map-leaf2-intake-20261102T073533Z.json.
These contain actual whole FDEs, CIEs, body hashes and raw GNU/LLVM exports.
The two map FDEs are each 830 bytes /170 rows; caller659/120; fixed32 115/37;
inserters each746/166; second leaf3839/781. This is an intake count, not a
final packet denominator or whole-program coverage.

## Explicit domain and helper contracts

Stable mode QWORD=1, limit=1000, initial counter C integer in [0,1000].
Reader state/input, output, stack and live heap objects are valid and disjoint;
ordinary preserving, non-faulting returns; exact memcmp/memmove/allocator roles.
No races, aliases, allocation failure, unwind, panics, arbitrary mode/limit,
native nominal types, or full surrounding greeting/connection claim.
C is the counter AT ENTRY to 1f646e0, not necessarily zero. In particular,
fresh enclosing message state must not be silently substituted for this C.
Fresh C=0 examples below describe this helper only.

Use credited primitive grammar: fixed32 raw bytes; each map count is an
accepted u64 variable integer charging8. Each original entry consumes key20
and paired value (four u64 words, four u64 words, raw byte), charges20+32+32+1=85,
has 29..93 wire bytes and65 active value bytes. Nonminimal integer widths
remain accepted. Each map has ordered20-byte keys, last original value wins.
Duplicates still count as original attempts and still incur the same charges.

## Observed caller order and active result

1f646f5 calls25594a0; only success BYTE0 proceeds.
1f64743 calls28916c0; only success BYTE18 proceeds.
1f64784 calls2890ea0; only success BYTE18 reaches success.
Both map results are root,height,len descriptors. The success path at
1f647c7..1f6484c forwards fixed32 to output[8,40), map1 to offsets40,48,56,
map2 to64,72,80, then writes outer QWORD0.
An empty map defines root0 and len0; its copied height cell is inactive and
must be excluded from semantic byte equality. Nonempty maps have height0.
No rearrangement between the two logical map fields occurs.
Pointers are abstract fresh owned identities, never invented runtime addresses.

All failure paths write outer QWORD1 with nested kind at output+8.
For selected kind0, needed is at+16; for kind3, expected/found at+9/+10;
kind2 has no active payload. Inactive error cells/padding are excluded.
First fixed32 or map1 failure skips all later work.
If map2 fails, its own partial map is dropped before it returns. Caller then
forwards that error and at1f64942 drops the saved complete FIRST map.
Thus real frees, when both maps had allocations, occur second-map then first.
Empty descriptors still undergo the drop call but have no allocation to free.
There is no rollback of reached input cursor or charge stores and no partial
map result is returned. Ordinary success transfers both maps; it frees neither.
The unwind-only first-map drop at1f64960 is preserved as observed context,
not included in the ordinary-return semantic claim.

## Primitive charge precedence

25594a0 checks C+32 overflow BEFORE store, stores the sum BEFORE limit
comparison, and checks input availability only after admission.
Within C in[0,1000], overflow is impossible for fixed32; if C>968, kind2 with
stored C+32 and unchanged input. If admitted but fewer than32 input bytes,
kind0 needed32-remaining, unchanged input and retained C+32.
Success consumes exactly32 bytes and preserves all32 in output.

For either map: count decoding charges8 first. After accepted original count K,
multiply96*K and addition to current counter must not overflow; these failures
do not store a wrapped reservation. Otherwise store reservation before checking
limit. Reservation admission occurs before any key/value input or heap allocation.
Before each original attempt refund96, then reach key20/value32/value32/byte1
charges in that order. Net counter change for a WHOLE original attempt is -11.
This applies to duplicates too. Partial failures keep the reached prefix charges.
Credited fixed/scalar error consumption and fast/slow type-error distinctions
must be carried through, not recomputed from remaining whole entry length.

## Joint admission theorem, independent of key cardinality

After fixed32 and first count, counter is C+40.
For original first count M, admission iff C+40+96*M<=1000 (with separate
overflow handling above). Therefore M<=10; M=10 requires C=0.
If all M entries decode, first-map counter is C+40+85*M.
Second count then leaves C+48+85*M. For original second count N,
reservation admission iff C+48+85*M+96*N<=1000.
Together these TWO inequalities, not independent map limits and not
C+48+85*(M+N)<=1000 alone, govern entry admission.

For C=0 the maximal second counts for first M=0..10 are:
M:     0 1 2 3 4 5 6 7 8 9 10
Nmax:  9 9 8 7 6 5 4 3 2 1  1
All admitted maps stay within one nonfull leaf (at most10 original entries
first, at most9 second), even before duplicate contraction. First-map/second-map
capacity11 guards and split branches are unreachable in this domain.
Each map allocates one1024-byte, alignment8 leaf iff at least one WHOLE entry
has been inserted; otherwise zero allocations. Internal failed prefixes cause
one free iff an earlier whole entry exists. Caller failure cleanup then frees
the first map iff it had at least one whole entry.

For C in[0,1000], M+N<=11 whenever both counts admit. Equality11 occurs only
at (C,M,N)=(0,10,1): first admission forces M<=10 and second admission for
M+N=11 requires C+1104-11*M<=1000, so M=10, then first inequality forces C=0.
For C>0 the sum is at most10. Cardinalities alone cannot predict admission.
If M=0, C in[953,960] permits first-map empty success but the second COUNT's
8 charge fails before its input is consumed. This is a separate later-failure
boundary from reservation failure and must appear in frozen cases.

After complete success final counter is C+48+85*(M+N); fresh-helper C=0
max983 at (10,1). Wire lengths for complete successful values range from
34+29*(M+N) to50+93*(M+N), including both count encodings1..9.
Therefore a fresh-helper maximal admitted11-entry example can consume1073
wire bytes while counter ends983, without violating limit1000. Logical charge
is not wire length. Arbitrary suffix bytes are left unconsumed.
This does not assert any enclosing message accepts that fresh-helper example.

## Dependency comparison and limits of comparison

The new map loaders have the same fixed20/value/count/drop dependencies as
1779. Inserter28570c0 has the same offset-indexed instruction listing as
credited285e420 after spelling local jump targets as SELF+offset and replacing
encoded RIP displacement while RETAINING its actual referent. Inserter285c600
has one remaining difference: its ordinary leaf call is1a8c700 instead of1a858e0.
Complete781-row leaf1a8c700 matches credited1a858e0 under those same display
normalizations, including actual RIP referents and nonlocal direct targets.
This exploratory listing comparison is NOT raw-byte equality, compiler/native
equivalence, or permission to copy inferred source. Retain originals. A final
packet must bind actual bytes/call targets/relocations with no invented masks,
and close the selected nonfull leaf and zero-height drop path explicitly.

## Remaining work before any submission

Revalidate exact helper/relocation/data closure using credited artifacts.
Freeze independent protocol/field mathematics before creating a checker.
Cover both map orders, duplicate original counts, key/value/word preservation,
every selected wire truncation, joint-budget thresholds, count overflow/store
precedence, empty-height masks, partial failure and real-free ordering.
Use corruption controls and explicit wrong-rule controls; normal/-O and replay
must agree. Run allowed repository checks; disclose excluded captured-instruction
test discovery, no Rust build, no hosted CI and all whole-component gaps.
No model/checker, branch, PR or completion credit has been created for this question.

