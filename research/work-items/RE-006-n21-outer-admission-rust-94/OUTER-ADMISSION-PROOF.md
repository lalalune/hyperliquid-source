# Fixed n21 first-short-run admission, private native intake

## Question and endpoint

Does the already recovered fixed-21 delegate have a concrete incoming native
route with sufficient scratch, and which original arrays take that route?

For the selected call to wrapper `0x4486d10`, with RDI pointing to 21 stable
unsigned qwords and RSI=21, the first natural run has length at least two. If its
length r is 2 through 10, the wrapper/core/adapter corridor reaches the entry of
`0x4918d30` with the original A unchanged, RDI=A, RSI=21, RDX=S, RCX=512, and R8
equal to all 64 bits of the wrapper's incoming opaque RDX. Here S is the actual
wrapper stack scratch base. This is conditional on the memory/frame premises
below. The claim ends at delegate entry; it asserts no new whole-sort outcome.

This closes a concrete admission gap left by #1524. #1455 owns the wrapper's
general scratch contract and monotone core; #1430 owns the selected collector
and its edge to the wrapper. Their existing work is credited, not counted again.
This intake remains private; no Rust projection or publication is authorized yet.

## Authenticated boundaries and CFG

The target is node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Addresses are linked ELF VAs and intervals are half open.
`OUTER-NATIVE-INTAKE.json` binds full target body/FDE/CIE bytes, unique exact
FDE intervals, and direct/relocated edges. The complete primary bodies have
matching continuous GNU/LLVM partitions: wrapper 269 bytes/75 instructions,
core 1,742/421, adapter 1,426/362 (3,437/858 total). Their conditional and
unconditional branch counts are 6, 56, and 41 respectively; call counts are
7, 6, and 8. These inventories describe complete bodies, not semantic ownership
of every branch. The existing delegate 903/254, seed 707/196 and collector
451/127 body identities are also pinned as predecessor boundaries.

Selected interfunction edges:

| Site | Encoding/target | Selected arguments |
| --- | --- | --- |
| `0x4486db8` | E8 to `0x4dbd490` | A,21,S,512,1,opaque context |
| `0x4dbd5d1` | RIP slot `0x57768a0`; unique RELATIVE type8/symbol0 to `0x4497a90` | A,21,S,512,0,0; context as seventh stack word |
| `0x4497acd` | E8 to `0x4918d30` | A,21,S,512,64-bit opaque context |

No indirect target is guessed from a symbol name. Ordinary call-return edges
are conditional on normal return and preservation of the selected callee-saved
registers. Exceptional/faulting behavior, wrapper LSDA cleanup and opaque failure
helpers remain outside this route claim.

## Wrapper: actual stack scratch and normalized flag

Five pushes at `0x4486d10..0x4486d18` consume 40 bytes; SUB RSP,0x1000 at
`0x4486d19` reserves 4,096 bytes. If wrapper entry RSP is W, then S=W−0x1028.
The scratch extent is [S,S+0x1000), 512 qwords. For n21 the wrapper's computed
scratch demand max(min(21,1,000,000),ceil(21/2)) is 21. The unsigned comparison
with 513 at `0x4486d46/4d` takes the stack arm `0x4486d7d`, sets R15=S and
ECX=512, and reaches `0x4486da7` without a heap allocator call.

XOR R8D followed by CMP RSI,65 / SETB R8B at `0x4486da7..dae` produces exactly
R8D=1, not an arbitrary nonzero word. The wrapper saves its incoming RDX in R14
and forwards it as R9; RDX becomes S. No source-array store occurs here.

## Core: exact unsigned run scan and pre-reversal branch

Core six pushes plus SUB RSP,0x2e8 put its stack pointer at T=S−0x320. It saves
opaque context as a qword at T+0x20, the normalized flag as a **DWORD** at
T+0x54, and A as a qword at T+0x10. The n21 small-count threshold construction
at `0x4dbd4dc..503` yields c=min(ceil(21/2),64)=11. The unsigned DIV uses
2^62/21, quotient 219604096115589900, remainder4; the saved ceiling factor is
219604096115589901. These are exact integer operands, not a floating estimate.

The initial offset R12=0, marker R10=1, stack count R11=0; the first remaining
count is 21. The remaining>=c branch at `0x4dbd58d` and remaining>=2 branch at
`0x4dbd624` reach full-qword loads of A0 and A1 at `0x4dbd64c/64f`.

| Decision | Actual native predicate |
| --- | --- |
| `0x4dbd653/656` | CMP A1,A0; unsigned JAE selects nondecreasing scan, including equality |
| `0x4dbd6ac/6af` | Full-qword current/previous CMP; JB stops ascending on current<previous |
| `0x4dbd6dc/6df` | Full-qword current/previous CMP; JAE stops descending on current>=previous |
| `0x4dbd6ec/6f1` | CMP r,[T+0x18]; JB takes `0x4dbd593` exactly when r<11 |

Each scan starts index2, tests only A2 through A20, and yields the first failed
edge's index or 21 when no edge fails. Thus valid n21 inputs never yield r1.
Ties continue the ascending run and stop the strictly descending run. The r11
boundary is excluded from this claimed first-short-run route. It is not a
prediction that all other core routes can never call this delegate later.

The short-run JB at `0x4dbd6f1` precedes the descending-reversal gate
`0x4dbd6f7`. Consequently even a descending run2..10 has not been reversed
before fallback. On this prefix, all stores are to the disjoint live frame;
array operations are qword reads. A is unchanged only up to the delegate call.

## Fallback and adapter: count, capacity and seventh word

At `0x4dbd593`, the test is **BYTE [T+0x54]**, despite the earlier DWORD spill.
The actual wrapper value1 takes its nonzero arm. Direct-core flag0x100 would
distinguish the operand width, but it is not a reachable normalized wrapper
flag in this n21 route and is labeled only an isolated arithmetic control.

The CMOVAE at `0x4dbd5a7` makes min(remaining21,32)=21. The core writes the
saved context to [T], passes A,21,S,512, zeros R8D/R9D, and calls the adapter
through the authenticated slot. No scratch-array data or A is written first.

The adapter's six pushes and SUB RSP,0x48 put U=S−0x3a0=T−0x80. It saves
capacity at [U+0x18] and R9=0 at [U+0x20]. Its unsigned count comparison at
`0x4497ab1/ab5` excludes n>=33; 21 takes the direct small-delegate arm. It reloads
RCX=512 and **QWORD** [U+0x80]=[T] into R8, so high context bits are retained.
At `0x4497acd` it calls `0x4918d30`. Context semantics are not inferred from its
register position or value. #1524 already binds the delegate's n21/cap>=37
premises; actual512 exceeds37.

## Memory/frame premises and exact unresolved runtime boundary

Require valid stable readable/writable A[0..21), ordinary nonfaulting execution,
and nonwrapping address arithmetic (including formed A−16/A−8 and A+168).
The selected chain's coordinates are:

| Point | Stack pointer |
| --- | --- |
| Wrapper entry | W |
| Wrapper scratch/core pre-call | S=W−0x1028 |
| Core after prologue | T=S−0x320 |
| Adapter after prologue | U=S−0x3a0 |
| Delegate entry | S−0x3a8 |
| Delegate after seven pushes | S−0x3e0 |
| Seed call plus its seven pushes | S−0x420 |

A sufficient alias premise is A's 168-byte source span disjoint from the entire
live [S−0x420,W+8) span, including scratch, saved registers, spills, return
machinery and the seed callee. Legitimate input in an ancestor frame above W+8
is allowed. This is an external runtime premise; no wrapper check establishes
it. The existing delegate uses the first37 scratch qwords (including16 auxiliary
words), not merely the first21. This intake asserts no physical-memory isolation
from a safe Rust slice, runtime pointer observation, allocator freshness, or ABI.

The credited collector passes a nonnull allocation as A after its call at
`0x4450242` through slot `0x576dfd8` to `0x54c06b0`. For21 valid rows it requests
168 bytes. Static intake of that allocator shows TLS cache/arena state and a
slow path; its output's runtime freshness/nonoverlap cannot be inferred merely
from its nonzero return. The allocator/TLS ownership invariant, source allocation
provenance and real call-state instantiation remain unresolved. No collector
reachability or arbitrary allocation guarantee is added here.

## Optional ordinary-return CFG closure, no new value claim

Conditional on ordinary delegate return, the adapter jumps `0x4497ad2` to its
balanced epilogue `0x4497fd6`. The core restores saved state and forms marker43
at `0x4dbd5e8`. Its priority/stack bookkeeping takes `0x4dbd810` to
`0x4dbdae6`, records marker1, advances R12 to21 at `0x4dbdb03`, then loops to
remaining0 (`0x4dbd570..586` → `0x4dbd600`). With one prior run it records43,
and the odd-marker test at `0x4dbdb11` takes the epilogue `0x4dbdb4c`.
There is no second adapter call or A access after the delegate on this selected
normal path. Wrapper n21 then skips deallocation at `0x4486dc4`, restores its
4,096-byte frame and returns. This is structural closure only, conditional on
the predecessor delegate contract; no new whole-wrapper sorting result is frozen.

## Frozen controls and remaining gates

`PRE-SOURCE-BOUNDARIES.json` freezes76 literal A21 cases:56 admitted and20
excluded, with all20 adjacent-order facts, run lengths, original-array bytes and
delegate-entry register projection. It separately freezes six synthetic address
relations and six isolated direct-core flag words. Synthetic addresses are not
observed runtime states; alias failures are outside the proof domain, not native
refusal predictions. r1 is an impossibility fact, never a fabricated input case.

`PRE-SOURCE-NATIVE-CONTROLS.json` preserves the pre-validation plan for16 exact
same-width native overlays. `STATIC-VALIDATION.json` SHA256
`fedb3ca515d7da7a7a035eda9a9303c4803d12b0678e1a7887f86f451339970c`
records all16 operative GNU/LLVM operand distinctions from64 tiny-fragment
decoder processes. These are finite static distinctions, never target execution
or executed array counterexamples. The flag-width control has no qualified
wrapper witness. Complete mutant ELF bodies were not created or executed.

No Rust source exists yet for this route. A future existing-component admission
relation could represent the value predicate and call projection under explicit
memory premises, but cannot manufacture allocator ownership or prove actual
runtime disjointness. Independent proof/freeze review is required first. Generic
counts, other natural-run paths, original ABI, unwind/fault behavior, outer
collection reachability, physical execution equivalence and the full component
gate remain open.
