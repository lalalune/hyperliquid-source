# Manual draft: node94 stream statistics keys and retained handles

Task RE-012 / transport; base966865f1637a29ce75b019e1bf11d5529cc6f519.
Node94 target SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. Addresses are linked ELF VAs. This is a conditional static
value/request argument, not captured execution or a complete transport gate.

## Distinct unknown and credited context

The connect caller passes a returned registration and its original address
fields to slot5773800. That slot's initial ELF relocation resolves to3d2a5a0.
This constructor acquires four statistics handles. The new question is what
identifies those handles, which resources an existing entry returns, which
fields a new entry initializes, and how the constructor places them beside the
registration. The selected bodies make no direct socket-option request;
opaque initializer/allocator callbacks remain explicit premises.

Prior packets traffic-recorder-instrumented-poll-94 and lz4-stats-report-94
identify consumers of the two tables, their report locks and statistics tasks.
RE-001-lz4-counter-order-94 establishes counter update/drain ordering and leaves
pointer ownership and the key flag meaning open. They retain all their credit.
The author's PR1672 supplies preceding first-request/copy context, and PR1685
supplies the separate readiness/socket-error/cancellation relation. Neither is
a runtime dependency of this packet. No can1357 inferred source is used.

Focused canonical searches find only those table/consumer references and a
neighboring FDE end. Four non-atomic live pages at selection contained334open
PR bodies. One broad prose-pattern match in1364 concerns HlChain branch-width
controls, with none of these addresses; no selected key/handle relation was
found. Repeat the live ownership check before submission.

## Premises and projection

The original address object is the fresh IPv4 variant used by caller20487f0;
its original32bytes were copied to self+20 at204882a..204882e. They remain
unchanged on the selected ordinary successful route. Thus self+22 and self+26
provide the same host-representation IPv4 word and port that preceded the
request. The saved address discriminant byte at state+20 is zero at2048c66,
so the constructor arm is reached rather than the adjacent rejecting/cleanup arm.

All state/result/stack regions and pointed objects are valid, appropriately
aligned where required, and disjoint. Once initialization and lock operations
return normally; the table is well formed and does not change while its lock
is held. Ordinary allocators return fresh disjoint storage of the requested
extent. Dynamic callbacks do not reenter and mutate these private regions.
Reference-count cells are distinct. Any hash/table reserve or timestamp helper
has the explicitly admitted ordinary result; their complete implementation,
allocator lifetime, fairness, Rust atomic ordering and unwind effects are not
established. Table validity includes control bytes consistent with occupied
keys and an eventual empty group on a miss. No cryptographic hash output or
whole Swiss-table implementation is reconstructed.

The constructor uses only direction selectors0and1. A general u8 selector2 is
not an admitted constructor state: lookup's occupied enum itself uses byte6=2
as a tag. Do not treat all256possible selector bytes as valid registry calls.
Unused copied padding is excluded from the value projection. Native bytes
remain complete; projecting defined fields is not a native-identity mask.

## Endpoint key and hash-update requests

3d0b281..3d0b295 and3d2ac34..3d2ac48 form

    K = low32(address) | (low16(port)<<32) | (low8(direction)<<48).

The upper byte is zero. The32byte traffic-entry table is at5786488, the40byte
LZ4-entry table at5786538. They are separate runtime namespaces; the same key
in one does not designate the other's resources. Both use the same hash
function3d2b290 with each table's separate16byte seed at table+20.

The packed key is NOT submitted as a raw seven/eight-byte hash update.
3d2b2dd reads byte6, zero-extends it to a u64 and requests an8byte update at
3d2b2f8. Then it requests4bytes from the address word at3d2b310 and2bytes
from the port word at3d2b32b. The ordered request transcript is

    LE64(direction), LE32(address), LE16(port), totaling14bytes.

The helper3d2b5d0's complete FDE is retained as context. Only these request
arguments and the absence of a key-byte7 read are claimed here, not a complete
hash algorithm, digest, source-library identity or native hash differential.
The two16byte hash-initialization constants and all direct targets are bound.

Both lookups3d276e0/3d275c0 filter a16byte control group using the upper7bits
of the returned hash. Every candidate then compares the port word, selector
byte and full address dword before accepting it. A matching fingerprint alone
does not select an entry. The traffic candidate is control-index*32 bytes
before the control pointer; the LZ4 candidate uses40bytes. The final entry
begins another32or40bytes before that candidate pointer, respectively.

The candidate comparisons are at3d27774/3d2777b/3d27781 and
3d27649/3d27655/3d2765b. Failed candidates are removed from the local bitset
before another candidate is checked. A group containing an ff empty control
byte ends the search after candidates have been tried. Otherwise probe steps
increase by16 with the table mask. On a miss with zero growth budget, the
bound reserve slots5776578(3d29a60,32byte rows) or5776570(3d29ff0,40byte rows)
are called before returning the vacant result. Their allocation/rehash
implementation remains a premise, not another claimed outcome.

## Existing entries and new-entry initialization

The occupied lookup result writes byte16+6=2. Both callers recognize it and
read the existing resources without allocating new cells or requesting a new
timestamp. For traffic, the three resource pointers are at entry+8,+10,+18;
for LZ4 they occupy the same relative offsets. LZ4 also reads the cached port
at entry+20 and selector at entry+22. A hit returns those cached fields; it
does not recompute them from the input arguments. For entries created by the
ordinary miss path below they equal the corresponding key fields.

On a miss,3d0b240 requests two24byte cells and one40byte cell from slot576dfd8,
which initially resolves to54c06b0. Every cell's first three qwords are set to
(1,1,0). The40byte cell additionally stores the result pair returned by
4ee3800(1) at +18(qword) and +20(dword). This packet treats that pair as an
admitted result; the earlier traffic-recorder packet's clock interpretation
is credited context. It makes no fresh clock measurement.

3d2abf0 instead requests three24byte cells, likewise initialized(1,1,0), and
does not call that timestamp helper. It stores the input port and selector in
the entry's cached tail. These are machine header/counter field values; naming
them strong/weak counts or counters is contextual inference rather than proof
of a particular Rust type/layout/Ordering.

The selected miss paths publish the key and pointers in their table row and
write the7bit control fingerprint (including its control mirror), then apply
the table growth/items adjustment. The bound constant at203480 is the pair
(0,ffffffffffffffff). Together with the old-control low bit, PSUBQ subtracts
that bit from the growth lane and increments the items lane, modulo64bits.
No concurrent table publication theorem follows from these sequential writes.

## Clone ordering and defined output

For traffic, the occupied join3d0b430 loads and LOCK-increments resource0,
then resource1, then resource2. LZ4 does the same at3d2ade2..3d2ae06 after
reading its cached tail. Each increment is followed by a signed<=0 abort
branch. On ordinary valid positive counts below2^63-1, all three increments
succeed. A newly initialized entry therefore has header0 values2after the
returned handle is cloned, while header1 and the initial data field remain
1and0. The table retains its initial references.

The literal count projection can also describe an aborting increment: it is
written before the <=0 test, and earlier increments are already visible. The
selected output stores occur only after all three tests. This is a local
machine-field projection, not proof that arbitrary synthetic counts represent
live Rust objects or that any abort/unwind resource cleanup is complete.

Traffic returns exactly the three pointers in24bytes. LZ4 stores the pointers
at output+0,+8,+10, cached port at+18 and selector at+1a. Its bytes+1b..1f are
not written by this body. The32byte copy performed by the constructor must
not turn those five padding bytes into claimed initialized semantic fields.

## Constructor integration

3d2a5a0 preserves the input address/port and requests handles in this order:
traffic selector0, traffic selector1, LZ4 selector0, LZ4 selector1. Its first
traffic call keeps the incoming address/port registers unchanged; the later
three calls explicitly restore them. It copies the32byte input registration
to output+0..1f, LZ4 selector0's defined fields into+20..3a and selector1's
into+40..5a, traffic selector0's24bytes into+60..77 and selector1's into+78..8f.
Finally it stores the original port word at+90. This is a field placement
contract: no byte claim is made for the two five-byte LZ4 padding regions or
the natural final padding after+91. Selector labels remain0/1; read/write or
inbound/outbound semantic naming needs its own consumer evidence.

## Initial ELF relocations are not runtime table contents

The addresses5786480and5786530 have initial RELATIVE relocations to3d0a680
and3d279a0, respectively. The selected code later uses those storage addresses
as the lock bytes after initialization. These are phase-dependent data, not
runtime indirect-call targets. The record of their initial ELF relocation
must never be described as a live callback or lock value. Likewise once words,
map contents and seeds are mutable runtime inputs, not values recoverable by
reading their initial file-backed bytes. Initializer/callback Location slots
are retained as context. Native operand identities and initial relocation
identities support provenance; they do not establish runtime initialization.

## Remaining qualification and limits

Retain8complete FDEs,5624bytes/1371GNU rows including the credited caller;
all raw GNU2.42/LLVM18.1.3 exports, selected initial RELAs, calls, constants
and dispatch tables. Several LLVM exports split LOCK prefixes; compare only
after explicitly joining adjacent standalone f0 records and retain raw splits.
No bytes are omitted or masked. Separate the initial-data slots from dynamic
callee bindings and the four once-word runtime reads from immutable constants.

Freeze independent mathematical expectations before the aggregate-field
checker. Cover truncation/byte order, the three update requests rather than
raw packed-key hashing, candidate key equality after fingerprint agreement,
hit/miss resource requests, clone order/partial-abort effects, cached versus
input tail values and constructor-defined placement. These cases do not
replace native binding controls, and no hash digest output should be invented.

All component gates and new recovered-byte credit stay unchanged. No captured
execution, networking, instruction/register evaluation, compiler/Rust/native
ABI/full hash or complete table/transport equivalence, hosted CI, or full
make test success is claimed. Full make test includes captured-instruction
evaluators outside this static-only authorization.
