# Private candidate: native seed producer and n21 preparation composition

This is a pre-Rust native proof candidate for independent review. It is not a
published full-sort claim or target execution result. Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The original A below means the 21 words at entry to delegate `4918d30` with
n=21, not the earlier collector/core array before any outer transformation.

## Authentication and admitted memory

Producer `4912a50..4912d13` is complete: 707 bytes/196 instructions, FDE
`f17fcc`, CIE `ce1518`, no LSDA. Body SHA-256:
`dd0aa09a10e58302a205c8e2ea0dac5c9f1428519d96b4a60c26bfb5c666f38a`.
Selected caller `4918d30..49190b7` is 903 bytes/254 instructions, FDE
`12a6ee4`, CIE `fbdc2c`, LSDA `b8638c`. Its body SHA-256 is
`9ae5e9107aca9a7ef4fd40d9b6dccee0cfa521a205a1422ea0a84b0ff9c05ed3`.
`SEED-NATIVE-INTAKE.json` also binds the complete core and adapter FDEs,
GNU/LLVM byte partitions, three selected direct E8 edges and the failure slot.
Coordinates are linked ELF VAs, half-open. No instruction normalization is used;
the retained textual exports normalize only the ELF filename header.

The producer reads eight raw unsigned qwords from RDI=P, writes eight
temporary qwords through RDX=T and writes eight destination qwords through
RSI=D. P[0..8), T[0..8), D[0..8) are valid, stable, nonwrapping and mutually
disjoint, and disjoint from both the selected caller and seed callee live
PUSH/CALL/saved-register/return machinery. Ancestor-frame temporary
storage is permitted. Faults, arbitrary data aliases, concurrency/MMIO and
failure/unwind behavior are excluded. This is the selected caller's actual
disjoint geometry, not a claim about all possible aliases.

All source/temp/destination value accesses are full qwords. AL/R8B/etc below
are comparison booleans or indices, not truncated input values. Input P is
never written on the normal path. Input rereads interleave with temporary
stores; disjointness/stability is needed to treat P as one immutable value
sequence. The seven pushes and balanced add/pop/RET preserve caller RBX,
R12, R14, R15 (and the other saved registers) explicitly from this body.

## First four-word network: complete case partition

Let input words be x0,x1,x2,x3. Define distinct index roles a,b,c,d such that
xa=max(x0,x1), xb=min(x0,x1), xc=min(x2,x3), xd=max(x2,x3).
Ties select a=1,b=0 and c=2,d=3. Instructions `2a63..2a85` establish this:

- XOR EAX,EAX then SETAE AL gives a in0..1 after CMP x1,x0;
- XOR R8D,R8D then SETB R8B gives b=1-a;
- XOR R10D,R10D then SETB R10B after CMP x3,x2 gives v in0..1;
- LEA R11D,[v+2] gives c=2+v; XOR R10D,3 gives d=3 xor v.

Let p=(xc<xb) and q=(xd<xa), using strict unsigned comparisons. The first
CMP at2a91 produces p. `CMOVB R15D,EAX` at2a9b changes the first middle
candidate from c to a when p. CMP at2a9f produces q: CMOVB EAX,R11D and
CMOVB R15D,R10D set the second candidate to c and the first to d when q.
The pointer CMOVB at2aaf selects the global maximum from d/a using the same q.
The repeated CMP at2ab3 restores p; CMOVB EAX,R8D selects b when p, and
CMOVB RCX,RBX selects global minimum xc when p. Consequently:

| p | q | global minimum index | global maximum index | two middle candidates |
| --- | --- | --- | --- | --- |
|0|0|b|d|c,a|
|1|0|c|d|a,b|
|0|1|b|a|d,c|
|1|1|c|a|d,b|

Each row uses all four distinct source indices exactly once. The order of
pair minima and pair maxima ensures the two candidates lie between the chosen
global minimum and maximum. CMP at2ac6 orders those two candidates; CMOVB at
2ad1 chooses their smaller value, and CMOVB at2adb chooses the other pointer
for the larger value. MOV/LEA and temporary stores between those operations
preserve the relevant flags. Stores2ad5,2adf,2ae6,2aed write T[0],T[1],T[2],T[3]
in that order. Thus T[0..4) is nondecreasing and an exact value permutation
of P[0..4), for all raw u64 values, including duplicates and high bits.
No original-source stable tie identity is inferred from equal values.

## Second four-word network

The block2af1..2b90 repeats that same partition for P[4..8):

| Role | Native construction |
| --- | --- |
| a,b for P4/P5 | XOR EAX/EAX and R10D/R10D; CMP2afe; SETAE AL2b02 / SETB R10B2b05 |
| c,d for P6/P7 | XOR EBX/EBX; CMP2b0b; SETB BL2b0f; LEA R15D,[RBX+2] / XOR EBX,3 |
| p | CMP R12,R9 at2b33, restored at2b51 |
| q | CMP R13,[P+a*8+32] at2b41 |
| middle candidates | CMOVB EBP,EAX2b3e; CMOVB EAX,R15D2b46; CMOVB EBP,EBX2b4a; CMOVB EAX,R10D2b5e |
| global maximum pointer | CMOVB R11,R14 at2b4d |
| global minimum value | CMOVB R9,R12 at2b62 |
| middle comparison | CMP R14,[P+a*8+32]2b6e, CMOVB RAX,RBX2b7a / CMOVB RBX,R10 at2b85 |

The identical four p/q rows therefore apply after adding4 to source indices.
Stores2b73,2b81,2b8c,2ba2 write T[4..8) in increasing temporary-index order.
The maximum is loaded at2b90, compared with the cached first-block maximum,
and stored to T[7] at2ba2; this compare does not change that stored value.
All eight temporary words are initialized before the first D store.

## Four fixed two-ended merge pairs

T now contains two sorted runs of length4. The first pair uses the cached
network minima/maxima rather than reloading the same T words. CMP right-min,
left-min at2bb8 and SETAE/SETB at2bbb/2bbe retire left on equality. CMOVAE at
2bc2 retains the right minimum only when right<left; otherwise it copies left.
D[0] and D[7] are stored at2bc6/2bc9.

The maximum comparison2b93/2b9f uses right-max versus left-max. ADC RDI,-1
after zeroing EDI gives right-back delta -1 on >=, otherwise0. CMOVA R8,R10
selects a right-loaded value only on >. SBB R10,R10 after zeroing R10D gives
left-back delta -1 on <, otherwise0. Thus back equality stores a value loaded
from the left but retires the right cursor. MOV/CMOV between the repeated CMP
and SBB leave CF intact. This distinction also holds for all three later pairs.

The remaining pairs explicitly load current fronts and backs from initialized
T. The following table identifies every unrolled cursor step:

| Pair | Front compare/booleans | Back compare/deltas | Destination stores |
| --- | --- | --- | --- |
|1 (t0)|2bb8; EBX left / R14 right|2b93/2b9f; R10 left / RDI right|0 at2bc6,7 at2bc9|
|2 (t1)|2bdc; R9 left / R8 right|2bf9/2c06; R13 left / R11 right|1 at2beb,6 at2c20|
|3 (t2)|2c39; EDX left / ECX right|2c52/2c5e; RAX left / RDI right|2 at2c46,5 at2c75|
|4 (t3)|2c8e; R12 left / BPL right|2ca9/2cb6; RSI left / R14 right|3 at2c9d,4 at2cbd|

Front deltas are0/1 words; back deltas are0/-1 words. Front comparisons are
unsigned, choose the smaller value and retire left on equality. Back
comparisons are unsigned, choose the larger value and retire right on equality,
while the stored equal value remains loaded from the left. Every front store
precedes its matching back store. The exact D store order is0,7,1,6,2,5,3,4.

## Exhaustion and final cursor checks

Let U be the immutable total order of the eight T words by
`(unsigned value, half, index)`, with left half first on equal values. After t
pairs, F=U[0..t) and B=U[8-t..8) have been retired. Native cursors are:
LF=#left(F), RF=4+#right(F), LB=3-#left(B), RB=7-#right(B). This starts from
the two sorted T blocks and literal zero/-one index deltas above.

For t<4 all memory candidates are valid: LF,LB in0..3 and RF,RB in4..7,
because every retirement count is <=t. If both half intervals have remaining
words, the ordinary unsigned front-left/back-right tie rules select ranks
t and7-t. If a half is already exhausted, its crossed cached endpoints are
retired lower/upper boundary words. Exhausted-left's upper cache is strictly
above remaining right (equal left sorts earlier), and its lower cache is <=
remaining right. Exhausted-right's upper cache is >= remaining left, and its
lower cache is strictly below remaining left (equal right sorts later).
The same two asymmetric tie rules therefore retire only the nonempty half.
Both boundary-cache words exist: at t<4 neither front nor back alone can
retire all four words, so early exhaustion needs nonempty sets on both ends.

The two selected global ranks remain distinct even in the final pair (two
remaining words). Hence the induction retires each of eight labels exactly
once, writes sorted U values to all D positions, and yields LF=LB+1 and RF=RB+1.
The body forms those exact final equalities, not a generic sortedness check:

- Left: LEA2cc1 includes pair3 front delta, LEA2cc9 adds pair4 front delta.
  LEA2cc5 includes pair3 back delta, SBB2cd2 gives pair4 back delta, LEA2cd5
  applies it and ADD2cd9 adds the exclusive-boundary8. CMP2cdd/JNE2ce0 compares.
- Right: LEA2ce2 includes pair3 front delta, LEA2ce6 includes pair3 back delta.
  LEA2ced adds pair4 front delta, LEA2cf1 adds pair4 back delta, ADD2cf5 adds8.
  CMP2cf9/JNE2cfc compares. Both guards therefore pass normally.

The fourth right-front boolean is only SETB BPL at2c99: upper RBP bits retain
an earlier arbitrary qword. Crucially XOR EBX,EBX at2c8c cleared all RBX, and
no intervening instruction writes RBX before MOV BL,BPL at2cea. That byte copy
therefore creates the full bounded0/1 RBX used by LEA2ced. Treating the whole
stale RBP as an index is incorrect. SETAE R12B also follows XOR R12D,R12D.
SBB RSI,RSI consumes CF from2cb6 because intervening CMOVA/MOV/LEA/MOV ESI,0
do not alter flags. The later ADD changes flags only after that delta is saved.

The balanced epilogue2cfe..2d0c returns. The only other call,2d0d, resolves
through unique RELATIVE slot576eaf8 to157a6d0 on a failed cursor check; its
transitive failure behavior remains unclaimed. A possible relative back index
-1 after the last pair is never read. Nonwrapping pointer formation includes
that temporary T-8 boundary. For the selected S-backed scratch it is inside
the wider admitted S allocation. No exception/fault/cleanup behavior is proved.

## Selected n21 caller geometry and left preparation

For n21 with scratchcap>=37, caller R15=A, R14=S, R12=10, RBX=21. It takes
the >15 seed arm. Direct E8 sites bind both producer calls:

| Call | Input P | Destination D | Temporary T |
| --- | --- | --- | --- |
|4918d71|A[0..8)|S[0..8)|S[21..29)|
|4918d86|A[10..18)|S[10..18)|S[29..37)|

The second P/D bases are LEAs with `R12*8` atd76/d7a (scale8), and the second T
is the n21 end S+168 plus64 atd82. These are disjoint source/output/temporary
spans; T2 ends exactly at S+296, the37-qword minimum. The proof above therefore
establishes, from arbitrary entry A and arbitrary initial scratch:

- S[0..8)=sort_u64(A[0..8)); S[10..18)=sort_u64(A[10..18));
- S[21..29)=sort_u64(A[0..4)) concatenated with sort_u64(A[4..8));
- S[29..37)=sort_u64(A[10..14)) concatenated with sort_u64(A[14..18));
- A is unchanged; S[8],S[9],S[18..21) are not touched by either seed.

If the caller entry stack pointer is C, its seven pushes and return storage
occupy [C-56,C+8). Each seed CALL and seven seed pushes extend the excluded
live range to [C-120,C+8). The admitted A/S buffers are disjoint from that
whole range. Seed calls reuse it sequentially; neither body adjusts this
normal stack depth internally. This exclusion permits legitimate S scratch
in a disjoint ancestor frame. It protects the delegate-entry A snapshot from
caller as well as producer stack stores.

The producer explicitly restores RBX/R12/R14/R15. The caller then resets
ECX=8 and RDX=11 atd8b..d93. Its left loop reads A[8],A[9] and no other source
words before reaching f4d. The full-qword strict-unsigned insertion proof in
#1524 shifts only the contiguous greater suffix, including equality-stop and
the offset8 guard before any lower read. Starting from the sorted eight-word
seed, two insertion inductions give S[0..10)=sort_u64(A[0..10)). The right
seed and both temporary spans are unchanged by these left steps. Thus the
prepared-state premises of the independently reviewed n21 continuation are
produced by actual native instructions, rather than assumed arbitrary buffers.

## Proposed full n21 value composition, pending peer review

At f4d, prepared S[0..18) is exactly sort(A[0..10)) followed by
sort(A[10..18)). A remains the delegate-entry A. The accepted continuation's
three right insertions yield S[10..21)=sort(A[10..21)), and its exact ten-pair
merge/center/final guards write all21 A words to
sort(prepared S[0..18) concatenated A[18..21)) = sort(delegate-entry A[0..21)).
All37 scratch words are then determined; none of their initial poison remains.
The old continuation’s80 arbitrary conditional prepared-state fixtures are
not thereby shown reachable: their S[21..37) guards were arbitrary, whereas
the actual producer fills those words with the four quartet sorts above.
Only the new original-A fixtures assert this constrained auxiliary content.
This is a candidate normal-value composition through one n21 delegate body,
not outer-core reachability, caller/collector end-to-end equivalence, generic
count sorting, a target ABI reconstruction or a full component gate.

`SEED-PRE-SOURCE-FREEZE.json` preserves80 original-A/initial-S cases and
complete post-seed, post-left prepared, proposed final-A/final-S states before
new Rust. It additionally freezes24 distinct four-word permutations and81
three-value duplicate patterns. The expected states use immutable integer
sorting and bisect splices, with all four p/q partitions represented. Cases
include asymmetric source/initial-scratch markers, high-bit and word32 edges,
duplicates, early exhaustion and minimum/maximum write counts. These are
static-derived expectations; the final composition must be reviewed before
any full original-A implementation or publication claim.
