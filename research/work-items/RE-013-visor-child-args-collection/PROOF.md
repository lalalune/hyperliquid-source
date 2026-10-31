# Conditional normal collection proof for visor child arguments

Target: visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
The owned FDE is `[0x61da10,0x61dd6c)`: 860 bytes, 220 native instruction
rows and 61 blocks. The retained projection has 33 branches and 16 call
sites. It models normal call/return edges; it does **not** establish LSDA,
unwind, allocator-error, trap or external error-helper behavior. All raw blocks,
including cold context, are bound. The argument below applies only to its
explicit normal domain, not arbitrary machine states.

The producer binds the actual operands/control edges; this document supplies
the complete induction for the claimed path. It is not a general automatic
machine-equivalence checker. The symbolic prefix/resource model supports the
contract and its boundaries, but does not execute or emulate captured code.
Independent semantic source/packet review is required before publication.

## Domain and external obligations

Let entry RSI point to a readable immutable 24-byte argument record containing
`(start,end,callback)`. No original Rust type is inferred. Require
`end=start+24*N`, `0<=24*N<=2^63-1`, with nonwrapping representable endpoints.
The whole descriptor interval `[start,end)` is readable and immutable. For
N=0 no descriptor element or callback is read/invoked. The argument record
itself must survive the prologue's saves; in particular it cannot overlap
those writes. Ordinary valid hardware call/return state is assumed separately
from readable stack storage.

At collection entry RSP=S with ordinary SysV alignment S mod16=8, saves occupy `[S-48,S)`, locals
`[S-120,S-48)`, and the original return slot `[S,S+8)`. The complete interval
`[S-120,S+8)` must be valid/nonwrapping and separated from the result record,
argument record, immutable descriptor and payload reads, and immutable code
and selected relocated bindings. Result24 and all allocated outputs must
be writable/disjoint from the immutable input/image and active frame/return
regions. The valid contents of the original return slot are an external
ordinary-call assumption; interval arithmetic alone does not establish them.
Other callees' frames must also be valid and cannot overwrite these regions.
For **every** used callback, allocator and memcpy call, explicitly require
SysV callee-saved register preservation (RBX, RBP, R12–R15, and restoration
of caller RSP), all live caller-local words, and the immutable input/image.
Fresh allocation or a finite ordinary hardware return alone does not imply
these preservation facts. They are external premises, not recovered callee
implementations. In particular R15/R14 retain first length/source across
allocation, and R12/R13/RBX/RBP/R14 carry live interval/output/payload/
capacity state across later allocation/copy calls.

Each used callback terminates normally, preserves caller locals/callee-saved
registers/immutable input, and returns pointer p in RAX and length l in RDX.
Pointer p=0 is a stop event, **before inspecting l**. For p!=0, require
`0<=l<=2^63-1` and an immutable readable nonwrapping l-byte source; l=0
requires no byte read. No nonnull Rust string assumption is imported.

The actual allocation target `0x70bf30` is opaque here. On every positive
request in the claimed run, assume a finite normal return of fresh writable
nonnull storage of at least the requested size, disjoint from all input,
frames, result and previous outputs. Its TLS/size-class implementation and
failure behavior are **not recovered**. The actual GLOB_DAT binding is symbol
6, `memcpy`; assume finite normal C byte-copy semantics on the stated
nonoverlapping source/fresh destination, with caller frame/input preservation.
The symbol binding is observed; that implementation contract is an explicit
external assumption. No allocator freshness follows merely from its label.

No selected error helper is reached in this domain. This is proved below
from nonnegative lengths, fixed-interval arithmetic and the nonnull resource
postconditions; it does not assume those error helpers never return. Their
normal fallthroughs, the UD2, cold cleanup and final external call boundary
remain in the record without a normal-result/termination claim.

For the actual UTF-8 callback, compose only the conditional normal-success
contract of [#1029](https://github.com/lalalune/hyperliquid-source/pull/1029),
with its own immutable-input/nonalias/valid-call domain. The callback entry
is S-128, so its additional adapter/validator frame is `[S-184,S-120)`.
Immutable argument/descriptor/payload/image regions and the result must also
avoid those callback writes, as well as this collector's frame. An
invalid UTF-8 callback's external error helper remains open. The proof below
also works for an abstract callback satisfying the stated normal contract;
it does not silently assume every descriptor is accepted by the actual parser.

## C1 — complete normal-flow binding

Authenticate one full immutable target snapshot. Derive its actual FDE/CIE/LSDA
coordinates, give GNU only the private 860-byte raw body, and require every
native row to equal that snapshot, tile it exactly, and agree with the fixed
complete block/edge ledger. Recompute relative branches, RIP slots and direct
calls from encodings. Normal-call edges include possible return from error
helpers; no noreturn inference is hidden in the graph.

The unrestricted normal-call projection reaches 176 instruction nodes.
The conditional selections justified below reach 144. These are scoped
projections, **not function coverage or full exception CFG denominators**.
Cold instructions after UD2 can be exception entries and are not globally
unreachable. Their raw context and the final open boundary at `0x61dd6c`
are preserved, without interpreting cleanup ownership or recovery.

## C2 — no elements and immediate stop

The prologue preserves the output address in RBX and loads start/end into
R12/R13. Equality at `0x61da28` goes directly to stores at `0x61da54`,
`0x61da5b`, `0x61da63`: raw output `(0,8,0)`. The common epilogue returns
the original output address in RAX. No callback, payload allocation or
record allocation occurs on N=0.

For N>0, load the callback from argument-record+16, call it with start, then
test RAX at `0x61da37`. A zero pointer selects the same raw empty result.
The returned length is not examined first, so it is unqualified on this
stop route. `C=max(4,N)` is **not** an output claim on either empty route.
These words are not named as an original Vec representation or a usable
allocation pointer.

## C3 — first nonzero pointer and length

For a nonzero first pointer, R15=l and RDX=start+24. The signed test of R15
excludes the negative-length error call under l's domain. `0x61da87` still
uses the original length test flags: intervening MOVs do not change flags.
Thus l=0 selects `0x61dab7` and sets the raw pointer word to 1, with no
payload allocation or copy. It is **not** a stop event.

## C4 — first payload copy

For l>0, save the source pointer in R14, request exactly l bytes through
slot `0x7e4b60`, and test the allocator return. Its assumed nonnull fresh
postcondition excludes `0x61dca3`. Save the copy pointer in RBP and invoke
actual `memcpy(copy,source,l)` at `0x61daaa`. Restore start+24 afterward.
There is no extra byte in this request or copy count; this controller does
not request/copy an extra terminator. This says nothing about later C-string,
OS or spawn conversion. Source bytes are unchanged under the stated copy and
alias assumptions.

## C5 — exact initial capacity arithmetic, only on allocation paths

Let M=N-1 and R=end-(start+24)=24*M. Because the interval is a nonwrapping
exact 24-byte multiple, R is exact and nonnegative. The bound
`24*N<=2^63-1` implies `R<=0x7fffffffffffffe0` (the largest valid multiple
is `24*N=2^63-8`). This proves the actual unsigned guard at `0x61dafb`.

At `0x61dac5`, SHR3 yields R/8=3*M. The actual multiplier
`K=0xaaaaaaaaaaaaaaab` satisfies `3*K=1 (mod 2^64)`. Hence IMUL's low word
is M, exactly, since M<2^64; this is not a claim of general division by 24
for arbitrary malformed intervals. CMP/CMOVAE chooses `max(3,M)`.
The LEAs form `request=3*(8*max(3,M)+8)`; after successful allocation,
INC R14 produces `C=max(3,M)+1=max(4,N)`. Therefore request=24*C.

For N<=4, request=96. Otherwise request=24*N<=2^63-1. All intermediate
LEAs and the increment are nonwrapping, request is positive, and the
zero-request fallback `0x61db32` is unreachable under this domain.
The assumed nonnull fresh allocator return excludes its failure edge.
This argument is for N>0 **after a nonzero first callback**; it must not
replace the separate raw empty output of C2.

## C6 — first row, one-element completion, and loop setup

The stores at `0x61db3a/3d/41` write the first raw row
`(l,copy_pointer,l)` at record-buffer+0/+8/+16. With l=0 that is `(0,1,0)`.
The local state records `(C,buffer,completed_count=1)`. If start+24=end,
the function already collected all N=1 elements and goes to output stores.

Otherwise N>=2. Save B=start+24, completed count j=1, and byte offset o=0.
The auxiliary remaining-size scratch is `24*(N-2)`. It will be decremented
by 24 after append and can wrap to -24 on the final iteration; it is not a
pointer, output count or input read bound. Since C9 excludes growth, no claim
requires that scratch to stay nonnegative after the final append.

## C7 — loop invariant, callback order and stopping condition

At `0x61db85`, for the next index j with `1<=j<N`:

- `B=start+24`, `o=24*(j-1)`, so callback input B+o=start+24*j;
- saved buffer/C are unchanged, and exactly j rows occupy indices 0..j-1;
- both saved completed counts equal j; previous descriptors were visited
  in increasing order and each produced a nonzero pointer;
- all stored positive payloads are fresh exact copies, empty rows are
  `(0,1,0)`, and input/frame/image invariants remain true.

The callback is called once with that descriptor. After return, save its
pointer in R15 and length in RBP, then restore B. The zero-pointer test
at `0x61db96` branches to output before inspecting length or allocating/
appending. Thus the result contains exactly the preceding j rows and no
later callback occurs. The sentinel test does not reinterpret a zero length.
For a nonzero pointer, the signed length test excludes its negative-length
error edge under the normal contract.

## C8 — later positive and zero-length records

If l>0, request exactly l bytes, use the nonnull fresh postcondition to
exclude `0x61dcbf`, and call actual `memcpy(fresh,source,l)` at `0x61dbcf`.
The source is saved in callee-saved R15 and the buffer in R14 across these
calls. Restore B/buffer and completed count j. If l=0, skip both calls and
store raw pointer word 1 in the local copy slot. The actual signed test
flags survive the intervening branch and select this case.

## C9 — growth is unreachable before every append

By C5, C=max(4,N)>=N. At each remaining append the pre-append completed
count is j<N, hence **j<C**. Both actual comparisons with C therefore
select direct append, not `0x61dc0c..0x61dc3c`. The generic helper
`0x620740`, its allocation arithmetic and its callee `0x620590` do not need
to be reconstructed to close this fixed-interval normal result. This is a
proved unreachable edge under the stated domain, not a claim that growth
is absent on arbitrary or malformed inputs.

The first append has completed count 0<C. After the final append the
completed count may equal C (e.g. N=4 or N>4); no strict-after-final bound
is claimed. Examples and the symbolic model support these boundaries;
the all-N result follows from C5 and the invariant, not their enumeration.

## C10 — row placement, count progress and termination

The later stores use buffer+o+24, +32 and +40, exactly row j's three words
at buffer+24*j. C9 ensures j<C, so they fit in the requested 24*C bytes.
They write `(l,copy_pointer,l)`. Increment j, save both completed counts,
form next=B+o+24=start+24*(old_j+1), and advance o by exactly 24.
The fixed interval makes next<=end and prevents endpoint arithmetic wrap.
If next=end, all N rows are complete; otherwise the loop invariant holds
with j+1<N. Every normal iteration advances j or returns at the zero
sentinel. Together with the finite normal-callee conditions, this proves
finite arrival at the local return, not just existence of a RET opcode.

## C11 — output fields and return

At `0x61dc84..0x61dc9e`, the saved completed count is written to output+16,
C to output+0, and buffer to output+8. No original private container/element
type is assigned to these word relationships. Common epilogue restores all
six saved registers and the original stack pointer before local RET
`0x61da7c`; RAX is the original output address. Valid hardware return-state
contents remain the explicit external call assumption.

## C12 — actual used callback and remaining obligations

The selected upstream witness at `0x5b920a` constructs this fixed interval
and callback descriptor, and its relocated word `0x7e6aa0` selects `0x48dc00`.
Those actual bytes/relocations are rebound; #988's whole lookup/table/accepted
argument grammar is not extended. #1029 establishes the callback's conditional
successful same-span return; this packet adds what happens to that span next.
In particular a valid empty UTF-8 span with pointerzero would still select
the collector's stop branch. No original nonnull str/Vec/String premise or
public parser/OS acceptance semantics is silently imported.

Opaque allocator/copy implementations, exception/error returns, cleanup
ownership, malformed descriptor intervals and all component/build/byte-equality
gates remain unqualified. #45 and #407's held lifecycle/unwind scopes are
not modified or reinterpreted.
