# Node115 TC reduction: bounded ordinary-return relation

Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. All addresses below are linked ELF VAs; ends are exclusive.
`bindings.json.gz` contains complete bytes, unique FDE/CIE records, all selected
instruction boundaries, direct/indirect edges, actual relocation writers, data,
referenced LSDA intervals and the complete incoming caller bodies. The source
does not call or interpret captured instructions.

## Scope and admitted domain

The seven subjects are two bridge/fold implementations plus their actual entry,
flat wrapper and outer join/merge. `rust/lib.rs` projects their established local
decisions from value snapshots and helper observations. It also projects the
249-byte per-item closure and the decision order in the 1,304-byte actual caller.
This is not a callable substitute for authenticated consensus verification.

| Subject | Full FDE | Bytes / instructions |
|---|---|---|
| Inline-row bridge | `0x5b37b70..0x5b38114` | 1,444 / 272 |
| Pointer-pair bridge | `0x5b3bd10..0x5b3c223` | 1,299 / 251 |
| Inline-row local fold | `0x564c120..0x564c4ad` | 909 / 187 |
| Pointer-pair local fold | `0x564c4b0..0x564c82d` | 893 / 188 |
| Entry / representation dispatch | `0x564b510..0x564b5e4` | 212 / 47 |
| Outer TLS route and merge | `0x5aac2c0..0x5aac694` | 980 / 183 |
| Flat producer setup and cleanup | `0x5b3dde0..0x5b3df09` | 297 / 78 |
| Subject total | seven complete FDEs | 6,034 / 1,206 |

Seventeen complete context FDEs add 9,033 bytes. Including unique incoming caller
bodies, the two native disassemblers and Capstone agree on 35 complete bodies,
26,297 bytes and 5,898 instruction boundaries. Complete selected-FDE overlap
enumeration gives exactly one containing FDE for each selected range. This is
not an exhaustive function or indirect-call census for the ELF.

The native correspondence requires ordinary valid mapped storage with stable
readable producer/context/row data, writable folder/output/flag storage, normal
stack/control state, and no aliases between those regions or helper-owned live
allocations. The Rust API is a safe value API, not the pointer ABI. Numeric
addresses in observations do not grant memory admission. For the finite fold,
the native end must be reached after exactly the supplied number of 16-byte or
104-byte steps, without address wrap, invalid dereference or an earlier fault.
Typed arrays deliberately strengthen availability of every projected byte.

All projected bytes supplied as snapshots must be defined native bytes. Native
success/error records can contain inactive or uninitialized padding. The model
does not manufacture those bytes: the caller supplies an observation, or omits
any claim about those bytes. In particular, returning a 72-byte synthetic
snapshot is not evidence that all 72 bytes were initialized by the closure.
The Rust implementation has no unsafe operations and does not allocate/follow
the supplied native addresses.

Helper ordinary return, output layout and noninterference are explicit premises.
Allocations must succeed where used. Cleanup/destructors must preserve the
selected output and other still-live records; requesting deallocation in the
projection does not authorize or perform it. The conditional caller additionally
requires that supplied history/collection/QC/parallel results and finite row
enumeration equal the observations actually produced by its helpers.

Unwinding, panic behavior, MMIO, invalid ownership, raw aliases, concurrent
mutation of payloads or container metadata, register/flag state not specifically
listed, and scheduling fairness/completion are excluded. Cancellation is modeled
by the byte observed at each actual load; no causal schedule is generated or
assumed. This permits analysis of a conditional local execution without asserting
that an arbitrary observation sequence is reachable in a concurrent run.

## Layout and entry

The raw result is 72 bytes, with tag at byte zero. `S=0x2e` is the branch's success
tag; local `T=0x2f` is a stop marker. A folder is 88 bytes: result `[0,72)`, opaque
qword at `+0x48`, and flag address at `+0x50`. Both folds preserve the latter
qwords. Consumers carry the flag address at `+0x10` and closure pointer at `+0x18`.

Entry `0x564b51b` initializes a stack byte to zero. `0x564b520..539` constructs
the consumer, including the same flag address and the incoming closure pointer.
It snapshots 32 bytes at closure `+0x18`. A nonzero first qword selects
`0x5aac2c0`; zero selects `0x5b3dde0` with the following 24 bytes. No arbitrary
nonzero tag is narrowed to one. `entry()` reports this representation decision
and initial zero byte; it does not claim private source types for the qwords.

The flat wrapper snapshots capacity, buffer, count; its two loads of count agree
under stable storage. It clears the local owned length, then unsigned-compares
capacity against count at `0x5b3de25..29`. Insufficient capacity reaches the
panic boundary. Otherwise it obtains worker count through the TLS/global-pool
path and `[pool+0x208]`, then calls the pointer bridge with logical length=count,
producer count=count, migrated byte zero, minimum=1 and the buffer address.
After the bridge returns it calls `0x5b12050`, then requests deallocation iff
capacity is nonzero, with size `capacity*16 mod 2^64` and EDX=0. The capacity
test precedes multiplication: a nonzero capacity may produce zero modular size.
`entry()` reports only this size observation, not a complete cleanup trace.
Normal return puts the original output address in RAX (`0x5b3dea3`).

## Bridge decision over the full supplied scalar domain

Let L be logical length, P producer count, M minimum, B budget, W the worker
count observation, a the producer start, and stride d in {16,104}. These are
independent u64 values in the projection; the actual flat wrapper's L=P and M=1
are separate caller facts. Migrated and cancellation are arbitrary bytes.

1. The flag is loaded through consumer `+0x10` at `0x5b37ba0` / `0x5b3bd40`.
   Any nonzero byte writes only `out[0]=S`; the other 71 output bytes are retained.
   This dominates count loading, halving and worker queries.
2. Let h=L>>1, an unsigned floor division. If h<M, use the local fold. If h>=M
   but migrated=0 and B=0, also use the local fold.
3. Otherwise, B'=B>>1. On nonzero migrated, a worker query occurs and the unsigned
   `CMOVBE` implements B'=max(B',W), including equality and zero W.
4. `SUB P,h` and `JB` at `0x5b37db3..db6` / `0x5b3beca..becd` reject P<h before
   task construction. `plan()` reports that boundary, not the panic routine.
5. A split supplies h and P-h, with second producer start `a+d*h mod 2^64`.
   The local path computes end `a+d*P mod 2^64`. These numerical results are
   defined for every u64 input; actual pointer traversal still needs the mapped,
   nonwrapping premise above.

The four regions in `oracle.py` are disjoint and exhaustive: cancellation;
noncancel/local; noncancel/split-eligible/underflow; noncancel/split-eligible/no
underflow. The source evaluates the observed branches sequentially. No count
budget or artificial restriction such as M>=1 is added to the single-step API.
For M=0 a zero-length split can be reported; no recursive termination assertion
follows. This is why the result is a decision projection, not a runtime executor.

Inline-row local producers use start/end and two context qwords. The bridge
swaps the two context qwords with `PSHUFD 0x4e` at `0x5b37c7f`; the fold passes
the address of the fourth local qword (`0x564c198`), giving the original consumer
`+0x18` closure pointer. Each inline row advances 104 bytes and passes key=row,
value=row+24. Pointer-pair rows advance 16 bytes and load key/value pointers from
offsets zero/eight. These pointer/context relationships are fresh node115 facts.

## Fold theorem and operation order

Both local folds first snapshot their producer (32 or 24 bytes). An empty
start/end pair copies the whole 88-byte folder to output without calling the
per-row helper or reading cancellation. The producer input itself is unchanged.

For each nonempty iteration, the local cursor advances before calling
`0x5942cc0`. There is no cancellation load before this first call. If the returned
tag is T, the fold exits with the original current folder, without reduction,
cleanup, folder write or flag read/write for that item. The consumed count
includes this call. Otherwise reduction obeys the following table:

| Current tag | Returned tag | Retained result | Cleanup |
|---|---|---|---|
| S | S | current complete 72-byte image | none |
| S | error | returned complete image | none |
| error | S | current complete image | none |
| error | error | current complete image | discard returned error |

For an error result, cleanup (if required) occurs first, then flag=1 is written,
then the selected result and preserved folder qwords are stored, then the fold
returns. There is no subsequent flag read on this branch. For S, it stores the
folder, loads the flag byte, and stops iff that observed byte is nonzero. Only
after a zero observation does it test whether the cursor reached end.

Key sites: stop tests `0x564c1ad` / `0x564c52d`; error flag stores `0x564c3a2` /
`0x564c722`; success-only reads `0x564c435` / `0x564c7b5`; final whole-folder copies
`0x564c448..480` / `0x564c7c8..800`. The final native RAX is the original output
address. `Fold` exposes folder/cursor/event observations, not all GP registers.

For the universal argument, before the first terminal item every processed
result and the initial folder tag are S, every observed flag is zero, the folder
is unchanged and the cursor has advanced exactly once per item. A terminal
item is the earliest T, resulting error, or nonzero post-success observation.
T has priority over error and cancellation on that item; error has priority
over cancellation. Therefore the least-terminal-index set used by the Python
oracle gives exactly the source loop's consumed prefix. The retained error is
the first element of `[initial error, processed returned errors]`. At most two
errors enter this list before termination; only the second is discarded.
Exhaustion is the case with no terminal index. Empty input is included.

The trace letters are observations in native instruction order: C per-row call,
D cleanup request, W flag=1 store, S folder store, R flag read, O final output
copy. They are not elapsed times or cross-thread ordering claims. Numeric cursor
addition uses wrapping u64 arithmetic; this does not expand native memory admission.

## Merge and literal cleanup

The bridges consume two 72-byte returned result lanes. In the pointer bridge
they begin at stack offsets 0 and 0x48 after `0x5b3bf8f`; the inline bridge uses
0xa0 and 0xe8 after `0x5b37e5e`; the outer wrapper uses 0x70 and 0xb8 after its
runtime call. The API calls the first lane `left` and second `right`. These names
do not assert which task finished first or establish global input-index order.
The worker/helper premises require that supplied lane observations match these
actual return slots.

The XOR/OR tests for both tags S lead to a single-byte S store, preserving the
output seed's remaining bytes. Otherwise the first non-S lane is selected. Both
errors select the first lane and discard the second. Error selection copies all
72 bytes to output before cleanup. This gives `merge()`'s truth table and trace.
The outer wrapper's CMOVE at `0x5aac563` is equivalent to the bridges' CMOVNE
selection (`0x5b3806a`, `0x5b3c179`) despite its inverted pointer initialization.

The discarded-error cleanup is inlined and tests raw tag values, not inferred
enum names. For tag 0x10 it examines descriptor offsets 8 then 32; tags 0x13 or
0x20 examine offset8 only; every other tag emits no request. At each descriptor
the first qword is length and the next qword is pointer. Nonzero length calls
slot `0x64df4a0` with RDI=pointer, RSI=length, EDX=0. A zero length skips the call.
The unique RELATIVE writer resolves this slot to `0x635de30`; its complete body
is retained as context. No allocator provenance or successful free is invented.
For raw tag T the merge treats it as an error; only local-fold callback handling
gives T special stop behavior. Ordinary callback reachability is narrower below.

## Shared byte and scheduler boundary

The flag loads/stores in these subjects are ordinary byte MOV operations, with
no LOCK prefix or fence around the selected accesses. Intel's documented basic
byte memory access atomicity supports a non-torn byte observation under ordinary
system-memory premises. It does not identify the original Rust atomic ordering,
provide a happens-before relation for other data, or guarantee prompt visibility
or fairness. See Intel SDM Volume3A, Order253668-085US (October2024), section10.1.1,
PDFpage286, “Guaranteed Atomic Operations”,
[official manual](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf),
and Rust's distinct [ordering contracts](https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html).

The outer route reads FS:-0x488 at `0x5aac322`. Nonzero initial TLS chooses
`0x59defb0` directly. If initially zero, it calls the global pool helper and reads
TLS again. Still zero chooses `0x4f0c230`; nonzero with `[TLS+0x110]` equal to the
global pool chooses `0x59defb0`; unequal chooses `0x59e9ce0`. The two TLS snapshots
are independent inputs to `entry()`, because the global helper may initialize
TLS. The no-TLS adapter receives data address `0x64b7070`, whose file word is
zero but unique RELATIVE addend is `0x5a398a0`; adapter `0x4f0c248` calls `[RSI]`.
That 60-byte TLS initialization boundary is retained without assuming its effects.

The inner wrappers `0x59ee480..59ee52c` and `0x59eedf0..59eee9c` route through
analogous TLS paths; their complete bytes and runtime targets are bound. Runtime
join bodies and incoming worker thunks are evidence of the actual connection,
not a complete work-stealing, wakeup or error-unwind reconstruction. In particular,
there is no theorem that every input is visited, the first invalid global index
wins, or cancellation prevents another worker's already-started call.

## Actual per-row helper and caller

`0x5942cc0..5942db9` is fully captured. It dereferences its context pointer;
snapshots a 16-byte prefix through context[0], certificate qword at
`[context[8]+0x88]`, and value qword at `[value]`. After a successful 56-byte
allocation it stores prefix at0, certificate qword at16, value qword at24, and
the 20-byte key at32. The union of stores is exactly `[0,52)`; bytes52..56 are
unclaimed allocation padding. It constructs message tag2 with the allocation
address and calls slot `0x64e64b8` with key, value+8 and context[16] snapshot.
That writer resolves to `0x57e8bd0`. Its deep indirect cryptographic calls remain
opaque; the model consumes the actual returned AL observation.

Any nonzero AL produces tagS, zero AL produces tag0x09 (`0x5942d56..56a`), writing
only output byte0. It requests deallocation of the 56-byte allocation and returns
the original output address in RAX. `closure()` projects initialized52 bytes,
call values, byte-only output update and RAX under ordinary cleanup. It neither
signs nor verifies a signature. In particular, normal calls to this helper do
not return T or cleanup-tag errors. Wider raw-fold tests exercise the local
decision domain, not a claim that the actual typed caller produces those tags.

The complete actual caller is `0x5960390..59608a8`. Its ordinary-return decision
order, projected by `admission()`, is:

1. Query history with certificate qword+0x40. A non-S result is copied in full.
2. Call collector `0x4dffc40` with the selected snapshot and certificate map+0x68.
   A non-S result is copied in full. Successful collection establishes cleanup
   ownership for every subsequent ordinary exit.
3. Enumerate map values, using the raw MIN64 NEG-overflow tree representation or
   the two-part inline ring representation. The projection consumes the actual
   finite enumeration; malformed containers and generic cursor semantics are
   not repaired or fabricated. Empty enumeration writes only output tag0x08.
   A nonempty enumeration folds unsigned maximum of value qword0, then requires
   equality to certificate+0x30 and strict unsigned inequality below certificate
   +0x88. Failure writes only tag0x0b (`0x59606ef..700`).
4. Call quorum slot `0x64e8780` (RELATIVE addend `0x595bc40`). Zero AL writes only
   tag0x08. Its weighted quorum algorithm is context, not reimplemented here.
5. Call nested-QC wrapper `0x595fd20`. A non-S result is copied in full.
6. Copy state+0x50's 16-byte prefix, convert the representation via `0x4da8e80`,
   build the closure, and call `0x564b510`. Supplied `parallel_output` denotes
   that helper's actual output image, not an invented fresh all-byte result.
7. Clean up the collected container and return original output address in RAX.

`admission()` trace H/C/I/Q/N/V/P/D records reached stages, not every nested call
or individual container destructor. D means the collection cleanup phase is
reached. In particular, it is different from the literal per-request D in fold
and merge traces. The required cleanup noninterference premise includes borrowed
helper errors and retained output bytes.

The maximum relation follows induction over the admitted finite sequence:
first value initializes the maximum, each `CMOVBE` selects the unsigned larger
value; equality does not alter the value. Early failure predicates dominate
later calls. This is the ordered-failure-set oracle's universal correspondence.
History query round+0x40, expected maximum+0x30 and certificate round+0x88 are
different native fields and are not silently equated.

## Migration and independent source limits

Historical own packet at commit `ef233f514883c4606e5d623ec73187d5e6653cac` was
search input. Its node94 184-byte rows, 80-byte results, 96-byte folder, large
success tag and nested-QC skip argument do not transfer. Node115 uses the two
producer forms, 72/88-byte images and byte tags above. Its caller does quorum
and nested QC before the parallel entry; historical caller ordering was different.
No deleted node94 tool, artifact or runtime file is required by this packet.

Official Rayon 1.10.0 commit `7543ed40c9a017dee32b3dc72b3ae819820e8366` supplies a
licensed structural comparison: `try_reduce.rs` has a shared AtomicBool, retained
Break ownership and left/right reduction; `plumbing/mod.rs` has the half/minimum,
budget and migrated-worker maximum decisions. Exact selected source bytes and
both MIT/Apache notices are retained. New analytical Rust is independently
authored from the stated node115 relation, with no Rayon runtime dependency.

The countercheck at v1.12.0 commit `c9ced185ae3508246a9eb70c8407a1199bb1b77f`
has byte-identical `try_reduce.rs`; inspected plumbing decision bodies also
match despite documentation/import edits. Node115's source paths say
`z_vendor/rayon`, not a crate version. Thus the vendor revision, patches, exact
private types, lockfile and compiled source identity remain unknown. The public
[try_reduce contract](https://docs.rs/rayon/1.12.0/rayon/iter/trait.ParallelIterator.html#method.try_reduce)
also leaves the chosen error unspecified when several exist, contradicting an
unqualified global-first-error claim. Source correspondence is not a byte match.

## Qualification and limits

The independent pre-adaptation oracle freezes 15,412 cases: 5,096 folds, 2,048
merges, 4,000 bridge decisions, 768 closure observations, 2,500 caller admissions
and 1,000 entry routes. It uses terminal-index/error-owner lists, an ordered
failure set and integer region partitions; the Rust uses sequential branches.
The pre-Rust timestamp explicitly acknowledges historical own Rust was already
available. The first static context span began inside the embedded Rayon path;
that preliminary exact capture remains under `validation/preliminary-static/`.
Final bindings expand the context without changing oracle, fixtures or source.

Rust1.94.1 opt0/opt3, each repeated, produce 61,648 exact expected observations.
Within each profile the rlib and client hashes repeat. All 36 compiled mutants
return normally with observable value differences. Four comparator corruptions,
eight parser controls, fresh target/FDE/relocation/operand corruptions and closed
manifest temporary-tree controls test admission and evidence integrity. The
archive contains all 258 exact command streams, with source and input hashes.
Artifact hash equality is a recorded build observation; offline packet replay
does not regenerate those binaries.

This is static-derived, independently computed semantic qualification of new
Rust on the host. It is not target execution, an instruction emulator, a source
build of the original vendored Rayon, or x86 compiled-byte equivalence. No
byte-window equality credit or component acceptance gate advances.
