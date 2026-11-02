# Private RE006 n21, first run20 and tail1

## Bounded question and ownership

The previous #1524 update closed first natural run2..10 admission to the fixed21
delegate. #1455 owns whole monotone runs. The nearest unclosed native value
route is initial run20 followed by one word, not all run11..20 tails.
Fresh intake scanned278 open PR titles/full bodies; only credited #1430,
#1455 and #1524 overlap those sort/core addresses. Existing published history
is unchanged. This intake is private and no new Rust source exists.

The proposed value statement is conditional: for original unsigned A21 with
exact first native run20, normal completion produces unsigned sorted A21,
under the node memory/frame premises and the ordinary imported-copy contract
below. It is a fixed21/r20 route, not arbitrary-count sorting or full component
recovery. The freeze's mathematical output oracle is `sorted(original A21)`;
rank-derived native stores/copies independently produce the same full array.

## Authenticated target and complete function boundaries

Node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. All intervals are half-open linked ELF VAs.
`NATIVE-INTAKE.json` binds complete exact body/FDE/CIE bytes for:

- wrapper `[0x4486d10,0x4486e1d)`269B/75 instructions;
- core `[0x4dbd490,0x4dbdb5e)`1742/421;
- adapter `[0x4497a90,0x4498022)`1426/362;
- small delegate `[0x4918d30,0x49190b7)`903/254.

Their full GNU/LLVM exports already live in predecessor ec71facb's outer and
fixed21 packets; those exports are reused, not duplicated. Core-to-adapter
RELATIVE slot0x57768a0 and adapter E8-to-delegate are authenticated predecessors.
No function boundary is inferred from nearby symbols alone.

## Admission and normalization

The selected wrapper supplies actual stack S and capacity512, normalized flag1
and opaque context. The core's count21 threshold is c11. Native full-qword
initial comparison chooses ascending on A1>=A0 unsigned; ascending continues
on >=, strict descending on <. An exact run20 means:

- nondecreasing A[0..20), then x=A20<A19; or
- strictly decreasing A[0..20), then x=A20>=A19.

At0x4dbd6f1, 20<11 is false, so fallback is skipped. Ascending goes directly
to0x4dbd7f7. Descending reverses exactly the first20 words. With half10 and
vector count8, two SIMD iterations execute eight128-bit stores. The four low
qword pairs at indices0..7 swap with reversed pairs12..19; PSHUFD0x4e swaps
64-bit lanes, not the32-bit halves inside each qword. Two scalar swaps then
exchange (8,11) and(9,10), four full-qword stores. A20 remains x throughout.
This reuse of the already proved reversal machinery is credited to #1455;
its application to a proper prefix and later merge is the new route.

## Marker/priority CFG, including delayed stores

The exact saved factor is ceil(2^62/21)=219604096115589901. Products below
are native low64-bit integer products, with nonzero XOR before BSR.

| Boundary | Offset | Prior/current markers | XOR power |
| --- | ---: | --- | ---: |
| Initial20 run |0|1 /41|2|
| Tail1 run |20|41 /3|1|
| Empty sentinel |21|3 /1|0 (explicit zero, not BSR)|

The first priority calculation is0 XOR0x3cf3cf3cf3cf3d04; the second is
0x3cf3cf3cf3cf3d04 XOR0x7cf3cf3cf3cf3d15. The stores at0x4dbdae6 save the
**previous** marker: first1, then41. After offset becomes21, remaining0
branches0x4dbd586→600; stack count2 and sentinel priority0 reach0x4dbd84d.
At0x4dbd8b7 the last saved priority1 is not below0, so one merge is forced.
Decremented stack index1 loads marker41. Current marker3 is kept separately.
Thus R13=20, RBX=1, RBP=21 and merge baseR12=A0.

Both markers are odd; the lazy-subrun adapter calls0x4dbd97e/9d0 are skipped.
Count/capacity guards pass min(20,1)=1<=512. After this merge, R10=43;
saved stack index1 takes0x4dbdae0/ae6, total<=offset branches0x4dbdb11,
and marker43's odd bit selects the epilogue, not the final adapter call.
No third run or second merge is admitted in this selected normal corridor.

## Tail1 is an actual no-array-access delegate call

At offset20, remaining1<c11 reaches0x4dbd593. Flag low byte1 is nonzero;
min(1,32)=1 is passed at0x4dbd5d1 through the known adapter. The adapter's
count1<33 path forwards A+160,1,S,512 and the full opaque seventh word.
Delegate0x4918d30 makes seven pushes, compares count to2, and its JB at
0x4918d3f goes directly to balanced epilogue0x4919082. It performs no A or S
access and no capacity check for count1. There is no seed call on this route.
Ordinary call/return and selected saved-register preservation are premises.

## Dynamic copy boundary, not a recovered local helper

Slot0x576dfe0 is ELF RELA info0x600000006/addend0: R_X86_64_GLOB_DAT,
dynsym6, undefined GLOBAL FUNC `memcpy`, GNUversion4 `GLIBC_2.14` from
`libc.so.6`. There is no local provider FDE in node94 for this binding.
Runtime provider selection/interposition, exact implementation, faults and
provider frame behavior remain unknown.

The value statement assumes ordinary nonoverlap `memcpy(dst,src,count)`
for the selected0/8-byte requests, with no writes outside requested destination
and the selected call preservation. Return RAX is unused. This is an explicit
external contract, not a claim that captured node bytes prove libc semantics.

At0x4dbda18/1e, left20>right1 picks right source A+160, not A0. The call at
0x4dbda2f copies eight bytes to S. R9=S, RDX=S+8, R14=A+160 and RAX=A+160;
the left>right branch0x4dbda41 selects the backward loop0x4dbda50.

## Complete backward relation, ties and terminal copy

Each iteration reads x=[RDX−8] and p=[R14−8] as qwords. CMP x,p feeds:

- SETB DIL: x<p consumes left;
- SETAE R8B: x>=p consumes tail;
- CMOVA RSI,RCX: loaded output bits are x only for x>p, otherwise p.

The qword is written at the current output pointer before cursor changes.
Left and tail pointers decrement8 only for their consumed side. On equality,
**loaded bits come from left while the retired cursor is tail**. Equal rawu64
values cannot establish distinct element identity; these are separate fields,
not a single ambiguous provenance/stability claim.

Let j=# {p in normalized first20 : p<=x}, the unsigned upper-bound rank.
All20−j words strictly greater than x shift right in descending index order.
If j>0, one final loop store places x's bits at A[j], consumes tail and leaves
the remaining left prefix in place. The call0x4dbd87e has destination A+j,
source S and count0. If j=0, all20 left words shift; the left-empty branch
sets destination A0 and calls the same import with count8 to place x there.
The array therefore preserves the original raw-u64 multiset and is nondecreasing;
this does not recover distinct element identity when bit values are equal.
The first copy happens before any merge output store; the terminal0/8 copy
happens only after loop termination. Logical copies are not physical provider
store traces. S0 becomes x and S[1..512) is unchanged under the external contract.

## Memory scope and freeze

Require stable valid nonwrapping A21, actual stack scratch and ordinary
nonfaulting calls. The selected node-owned chain reaches S−0x3e0 (tail1
delegate's pushes), not the seed's deeper frame. A is disjoint from the node
live span[S−0x3e0,W+8), S=W−0x1028. The dynamic provider's actual frames must
also not alias either buffer; no concrete provider stack lower bound is known.
Source/scratch disjointness and runtime allocator ownership remain external.

`PRE-SOURCE-FREEZE.json` preserves48 admitted literal arrays: all20 possible
ascending insertion ranks0..19, all20 descending ranks1..20, and eight
duplicate/high-bit/tie cases. Six exclusions have no new final-output prediction.
Full original/post-normalization/final A21, scratch-prefix guards, exact rank,
ordered loop observations and both0/8-byte copy calls are frozen before Rust.
The outer512-word untouched-scratch statement is a quantified static premise,
not512 observed runtime values. `PRE-SOURCE-NATIVE-CONTROLS.json` preserves12
planned finite operand distinctions, including a value-unobservable tie-provider
variant. The separate STATIC-CONTROL-RESULTS.json receipt (3a16efb23f5d9bef653e3110776fbb61943e886e5899a2ed746c332c437c6b3e)
records12 operative static distinctions/48 decoder processes and96 retained raw
channels. No native control is counted as an array-output control or executed.
This establishes decoding only, never target execution.
`CONTROL-ERRATUM.json` corrects the frozen description of
`remaining-copy-wrong-destination`: R15 is minimum count1 at that point, so its
MOV overlay selects address1, not scratch. Original bytes/plan are preserved.
That unsafe-address variant is only decoded inertly; it is never executed or
counted as a safe source-model/array-output control. The erratum must accompany
the frozen controls in any later manifest or receipt.

No Rust source, captured instruction execution/evaluation, new tooling,
allocator reconstruction, generic run11..20 result, original ABI, libc identity,
fault/unwind or full component gate is claimed. Next decision is whether the
explicit imported-copy contract is an acceptable boundary for this qualified
normal value reconstruction, after independent proof/freeze review.

The original source-control witness plan53b8388f is preserved.
RUST-PLAN-ERRATUM.json records a pre-source mathematical falsification of its
signed-control witness, which did not reach a cross-sign comparison. Corrected
PRE-SOURCE-RUST-PLAN-v2.json uses the already frozen MAX-tail case. All original
arrays and expected wire bytes remain unchanged; seven planned source controls
change arrays and three are observation-only. No source control has run yet.
