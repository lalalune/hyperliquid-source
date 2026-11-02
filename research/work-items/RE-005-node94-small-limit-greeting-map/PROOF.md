# Small-limit greeting-map relation: manual pre-checker draft

Target node94 is91774280bytes, SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Base966865f1637a29ce75b019e1bf11d5529cc6f519. All addresses are ELF VAs.
This is a manual draft before a new oracle/checker, not a qualification receipt,
captured execution, Rust implementation, recovered-byte credit or completed gate.

The bounded question is the result and ordered effects of map decoder2890b60
with mode QWORD1 and logical limit1000. Its count-prefix charge and96-per-attempt
reservation bound every admitted invocation to at most10entry attempts. This
is enough to exclude a full11-key leaf and every split/ancestor route. A
stronger9-attempt bound for one outer caller was a provisional hypothesis;
this theorem does not require or claim that unclosed outer-prefix argument.

## Scope, input and dependencies

Admit any u64 initial charge C, immutable nonwrapping valid byte slice at most
isize::MAX, and separated stable state/output/stack/new allocations. Mode and
limit remain exactly1/1000. Native helper calls return ordinarily and preserve
unrelated state; memcmp compares exactly20unsigned bytes lexicographically,
memmove preserves overlapping moved segments, and allocation/free satisfy
the explicit valid disjoint ordinary-return request contracts. Allocator/TLS,
raw pointers, aliases/faults/races, original types/ABI and unwind are excluded.

The four primary context FDEs already retained are2890b60..2890e9e (830bytes,
170GNUrows),285e420..285e70a (746/166),1a858e0..1a867df (3839/781), and
28b0ae0..28b0e2d (845/209):6260bytes/1326rows. Full raw exports include
unreachable split/ancestor/terminal blocks. This denominator is static identity,
not semantic coverage or newly recovered code. Only addressed mode1/1000
reachable routes are interpreted. Remaining call/data/RELA qualification is
required separately before any public claim.

Count decoding2558c90 and its scalar fast/Reader/error grammar are credited
canonical/peer1365 context. Fixed20key2558e70 is peer1535's leaf family context.
Paired value25587d0/2558ee0 is authorPR1742's separate mode1 theorem: eight
variable-width u64s then one raw byte, fixed reached charges32/32/1, active
result/error forwarding and partial input effects. Generic stream/hash schema,
peer1454byte and peer1497owned-byte collection remain credited; no primitive
clone, generic schema or another open PR's implementation is newly claimed.

## Count and reservation precede entry work

2890b77..2890b88 calls2558c90. In admitted mode1 it first charges8. C>MAX-8
returns kind2 with no store/input advance; otherwise C'=C+8 is stored before
testing C'<=1000. Limit failure retains that store and consumes no prefix.
The scalar count read then consumes its actual variable width or forwards its
active error and partial cursor. A failed count read never reserves entries,
creates a map node or releases a node.

Count success yields M. At2890b8f..2890bb3, nonzero QWORD mode multiplies M
by96 with unsigned high-half overflow detection, then adds C'. Either overflow
returns kind2 before a reservation store. Otherwise R=C'+96*M is stored before
its unsigned limit comparison; R>1000 returns kind2 retaining this store. The
count prefix remains consumed and all following bytes remain. No body byte is
read and no map allocation occurs on these failures. M=0 still executes a
same-value reservation store R=C'; do not erase that store from its transcript.

Admission proves C'>=8, R<=1000 and M<=floor((1000-C')/96)<=10. No bound on
distinct keys is substituted for this original decoded count. The native loop
decrements the original attempt counter regardless of duplicate replacement.

## Refund, fixed charges and failure ordering

Before attempt j (zero based, j<M), after j prior successful attempts, the
counter is R-11*j. At2890c20..2890c38 it checks counter>=96 and subtracts96.
Then fixed20key reading charges20; the paired value charges32,32,1 on reached
stages. Success therefore leaves R-11*(j+1). The reservation is an admission
accounting cost, not an input width or the final counter cost per accepted row.

The unsigned subtraction guard is true: before a remaining attempt,
R-11*j = C'+96*(M-j)+85*j >=96. Every reached entry charge is at most the
previous admitted R, and the maximal completed charge is R-11*(j+1)<=1000.
Thus under the stable actual helper premises no entry-stage overflow or limit
failure is possible after reservation admission. Retain every native guard and
error block, but do not invent a reachable budget failure for this domain.

A key shortage retains the post-refund charge20, consumes no key bytes, and
returns kind0 needed20-remaining. Previously completed count/entries stay
consumed. A value error retains the successful20key bytes and all actual
reached32/32/1 charges and scalar cursor effects of PR1742. The logical map
result is an error; it does not return a partial map. The remaining original
attempts are not processed and there is no counter/input rollback.

A success row consumes20raw key bytes plus9..73value wire bytes, hence29..93
wire bytes. It contributes85logical entry charge after its96refund. Each key
is exactly20bytes; each value is the eight-word/raw-byte logical result in
decode order. No signature/hash nominal type or cryptographic meaning follows.

## Active output and temporary repacking

The map helper's result layout differs from the paired value's QWORD outer
tag. Map success has BYTE status18 at0 and header QWORDs root at8, height at16,
length at24. On error the map's BYTE kind is at0; kind0 additionally defines
QWORD needed at8, kind3 BYTE expected at1 and found at2; kind2 has no active
payload. In particular the paired wrapper's outer QWORD1 is removed by the
copy of its nested error from paired-output+8 at2890e32..2890e4e.

The key success payload starts one byte after its status; the caller retains
its16+4defined bytes. The paired value is repacked through stack temporaries
at2890c9e..2890dc2 into eight words and a raw byte in original order. Physical
value stride is72bytes, while only65payload bytes are defined by the producer.
Seven padding bytes remain outside the logical comparison. Wider native copies
remain intact as evidence; no zero-padding or full initialized ABI is asserted.

For M=0,2890be4/2890bed initialize only root=0 and length=0. The middle stack
header word is not initialized before2890de2 copies it to the output. Root0
therefore has no active height observation; never turn that copy into height0.
There is no allocation or release for an empty result.

## First leaf and inductive no-split invariant

On a successful first entry285e420 sees root0 and selects285e62a. It requests
0x400bytes, sets node parent0 and count0, writes the new header root and height0,
then writes the20byte key and72byte value stride, increments node count and
header length. The logical value projection compares only its65defined bytes.
Null allocation/error dispatch is outside ordinary return, not an invented OOM
result. No allocation happens before the first whole entry is successfully read.

Inductive state after j>0successful attempts: one valid leaf of height0, parent0,
n distinct20byte keys in strictly ascending byte order, 1<=n<=j<=10, associated
last supplied values, and matching node/header counts. There are no children.

285e457..285e4d1 searches keys in ascending index order using actual20byte
memcmp requests. It advances while input key is greater, selects equal-key
replacement on zero, and stops at the first greater key or leaf end otherwise.
Its value pointer progresses in72byte strides in parallel with20byte key
strides. With height0 the missing-key descent test at285e4e5..285e4ee borrows
immediately, so it cannot read a child slot at+0x400.

For an equal key,285e502..285e565 saves the former72byte value to the ignored
return record and replaces it from the new value. It does not increment node
or header counts and does not replace the key. The caller ignores the old-value
result; there is no value-specific drop request on this selected route. Logical
last-writer-wins behavior is an observed value association, not a source type.

For a missing key after j<M attempts, n<=j<=9<11. The delegated1a858e0 therefore
takes its nonfull branch at1a85901..1a85905. It inserts at the search index:
an end insertion writes the new key directly; a middle insertion requests
memmove of20*(n-index)key bytes and72*(n-index)value-stride bytes one slot
right before writing the new cells. At1a85a08..1a85a43 it increments count,
writes the new72byte stride, then jumps directly to1a8667f. The intervening
split/ancestor implementation is unreachable in this inductively produced
domain. The return retains the leaf pointer/height0/index;285e6c1 increments
header length exactly once. The resulting distinct count n+1<=10 preserves
the invariant. No branch ever reaches full11keys on an insertion attempt.

The sorted logical output is consequently the last value for each key among
all M input rows, with length equal to the number of distinct keys. The loop
still consumes all M rows and charges each attempt, including duplicates.
Input order, sorted key order, attempted-row count and distinct count are
separate observations and must not be conflated.

## Cleanup after a partial input failure

Both entry-error branches invoke28b0ae0 on the produced map header. If root0,
its first test returns without reading height or requesting a release. After
at least one completed entry, the invariant provides height0, a single leaf,
matching positive length/count and parent0. The loop enumerates that count
without descending a child; on the final entry it reaches28b0d7e, reads
parent0 and takes28b0dd3..28b0deb. Exactly one release request is made for
(root,0x400,flags0). No per-value release, second node or0x460internal-node
release is reached. Actual allocator/cache/free internals remain premises.

The destructor does not need to initialize/clear the discarded stack header.
Do not expose a freed pointer as a valid returned map or assign values to its
inactive fields. With no successfully completed entry there is no node to free;
with one or more there is exactly one leaf release before the error return.
Success retains its node for the outer owner; it makes no release request.

## Remaining closure and next work

This manual draft needs fresh canonical/current peer ownership review,
complete selected-call and initial relocation records (including actual
memcmp/memmove/allocation/free bindings), explicit scalar dispatch/data and
terminal-coordinate handling, then constructive expectations sealed before a
new independently formulated checker. The full raw FDEs are required even for
excluded split/error routes; do not claim their semantics or mask their bytes.

All-limit maps, mode0/other raw modes, arbitrary supplied preexisting trees,
allocator/unwind/fault behavior, source type/ABI, exact physical padding,
stronger outer9-entry provenance, full greeting/connection and component gates
remain outside this theorem. Do not change shared registries/gates. No compiler,
captured instruction evaluator, network service or captured target has run.
