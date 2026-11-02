# Private native n21 right preparation and normal merge completion

Target node94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Main base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
The primary complete FDE is `4918d30..49190b7` (903 bytes/254 instructions),
FDE `12a6ee4`, CIE `fbdc2c`, LSDA `b8638c`. The selected contiguous normal
corridor `4918f4d..4919091` is 324 bytes/92 instructions, SHA-256
`2a783e35613d8d63d9c3ec5df4e6553e29c5b6fc94c3bc8cd171b73540b5ccf2`.
GNU/LLVM partitions agree with authenticated file-backed bytes. Full four-body
bindings are in `NATIVE-INTAKE.json`. Coordinates are linked ELF VAs, half-open.
This document precedes Rust source. No captured instructions are evaluated.

## Exact admission, observations and unknowns

Entry is at `4918f4d`, with RBX=21, R12=10, RCX=8, RDX=11,
R14=S and R15=A, and the function's ordinary valid live frame. These constants
are derived from the qualified n21 prologue and the earlier left-loop closure
in #1524, rather than an arbitrary generic merge interface. A contains 21
qwords; the original full delegate requires scratchcap >= n+16=37. The selected
corridor accesses only S[0..21); S[21..37) is retained as an unchanged guard.
A, S and the callee's live frame/return machinery must be stable, valid,
nonwrapping and disjoint. Ancestor-frame scratch is allowed. Faults, MMIO,
concurrency and arbitrary overlaps are outside this relation.
Nonwrapping pointer formation includes the possible temporary S-8 address;
that address is not dereferenced. The safe value projection uses an integer
relative back index -1 for this case, not a fabricated allocation before S.

The prepared left S[0..10) must be nondecreasing as unsigned u64, and the
prepared right seed S[10..18) must be nondecreasing as unsigned u64. These are
explicit input premises. #1455/#1524 do not establish that the opaque seed
produces them or that every supplied prepared state is reachable from the
outer caller. The three current source values A[18],A[19],A[20] are unrestricted.
No seed implementation, original ABI, full generic sort or component gate is
claimed. Both native failure/unwind paths remain outside normal completion.

The value projection is the complete final A[0..21) and S[0..37). A chosen
logical write sequence, insertion positions, merge cursor/provenance choices
and final cursor equalities can also be compared; none is a recovered native
return object or a claim about compiler physical store traces.

## Right-run preparation: all three iterations

At f4d, RAX=S+80. RCX=8 < RDX=11 makes the unsigned admission JAE at f54 fall
through. RSI=A+80, EDI=64. The j=8,9,10 iterations each:

1. f82 loads full qword `A[10+j]` into R8 and f86 stores it to `S[10+j]`.
2. f8a loads the full predecessor `S[10+j-1]`; f8f compares unsigned values.
   JAE at f92 takes the no-shift join on incoming >= predecessor, including
   equality. The initial append is still a real native store on this path.
3. On incoming < predecessor, R9 starts as byte offset 8j. fa0 shifts that
   predecessor one qword right. fa4/fa8 test offset 8 before any lower load.
   At the front, f70/f73 stores incoming at S[10]. Otherwise faa loads from
   `S+80+offset-16`, faf decrements offset by8, and the unsigned JB at fb6
   repeats while incoming < predecessor. fb8/fbb then address the final store
   at f73. Thus only the strict-greater contiguous suffix shifts.
4. f76 increments j, f79 adds8, and f7d/f80 exits exactly at j=11. There are
   exactly three incoming loads, always A[18],A[19],A[20].

The standard insertion induction is valid here because the admitted seed is
sorted: each new word is inserted after all equal words, preserving order and
the exact multiset. The complete right run is sorted S[10..21) afterwards;
left S[0..10) and guards S[21..37) are unchanged. Per insertion the store
sequence is append, zero or more predecessor shifts from right to left, then
one final incoming store only when shifting occurred. The maximum is 10+11+12
scratch stores (27 shifts plus three appends and three final stores).

## Exact ten-pair merge and tie provenance

fbd..fd3 initialize output-front t=0, output-back b=20, right-front RF=10,
left-front LF=0, right-back RB=20, left-back LB=9, and spill count21 at [RSP].
For each t=0..9, fe0/fe3 load S[RF]/S[LF] as full qwords. CMP right,left at
fec supplies both SETAE(left advance) and SETB(right advance). CMOVB at ff7
chooses the unsigned smaller value; equality keeps the left-loaded value and
advances LF. The front store at 9014 is A[t].

ffb/ffe load S[RB]/S[LB] before either output store. Back comparisons at
9001 and 900d are identical `CMP right,left`. MOV EBX,0 does not change flags;
ADC RBX,-1 at 9009 gives RB delta0 when right<left and -1 otherwise. The
second CMP reinstalls CF; CMOVA at 9010 selects right only when right>left.
MOV stores at 9014 and MOV R9D,0 at 9018 do not change CF, so SBB R9,R9 at
901e gives LB delta-1 precisely when right<left. Thus:

| Back comparison | Stored register value came from | Cursor retired |
| --- | --- | --- |
| right < left | left | left |
| right = left | left | right |
| right > left | right | right |

The equality row must not be called one common source choice. It has equal
values but distinct load provenance and cursor identity. 902c then stores the
selected qword to A[20-t], after the front store. LEAs update both front and
back pointers, INC/DEC update output indices, and 903b/903e repeats until t=10.
The complete output-store order is 0,20,1,19,...,9,11, then the center10.
No exhaustion branch exists in these ten pairs.

## Strong rank/cursor invariant, including early exhaustion

After right preparation, form a mathematical immutable sequence T of all21
words sorted by `(unsigned value, half, index within half)`, with left half0
before right half1 on equal cross-half values. This total-order device is a
proof object, not recovered source/ABI data. For t in0..10 let F=T[0..t) and
B=T[21-t..21). The precise invariant at pair entry is:

- LF = number of left-half labels in F;
- RF = 10 + number of right-half labels in F;
- LB = 9 - number of left-half labels in B;
- RB = 20 - number of right-half labels in B;
- A[0..t) and A[21-t..21) equal those respective T values.

At t=0 these are literal fbd..fd3 initial values. Because 2t<=20, F and B do
not overlap. An unexhausted half presents its first/last remaining word as
the two candidates. When both halves have remaining words, the unsigned
comparisons with front-left/back-right cross-half tie retirement choose
exactly T[t] and T[20-t], at distinct global ranks.

The missing exhaustion branches require four additional cases. Suppose a half
has no remaining word at a pair entry t<10. Its front pointer crosses its back
pointer, but the following cached endpoints are still valid original words:

1. If left is exhausted, its front candidate is the first left word already
   retired from the back, at a rank above 20-t. It must be strictly greater
   than every remaining right word: equal left values sort before right,
   contradicting that larger rank. Therefore front selects right. Its back
   candidate is a left word retired from the front at a smaller rank, and is
   <= every remaining right word; back selects/retire right, including ties.
2. If right is exhausted, its front candidate is a right word retired from
   the back at larger rank, and is >= every remaining left word; front selects
   left including ties. Its back candidate is a right word retired from the
   front at smaller rank, and must be strictly less than every remaining left
   word (otherwise equal right values would sort after left). Back selects left.

These candidate words exist: at t<10 neither front retirement nor back
retirement alone can consume all10 left or all11 right words. If a half is
exhausted, both its front and back retirement sets are nonempty. Their boundary
words give the two cached candidates. This also closes all no-live-word cases,
without inventing an out-of-bounds sentinel or reading S[-1]/S[21].

For memory bounds, at every pair t<10 each retirement count is at most t.
Consequently LF is in0..9, RF in10..19, LB in0..9 and RB in11..20, independent
of whether the logical interval crossed. All four qword loads remain within
S[0..21). The candidate lemmas preserve the exact four cursor formulas and
both output ranks, completing the induction. They are stronger than assuming
that a generic sorted merge has exhaustion guards.

## Center and final normal-return guards

After ten pairs, T has exactly one unretired word at rank10. 9040 adds8 to the
left-back pointer, producing its exclusive boundary LEX=LB+1. 9048/904b tests
the actual saved odd count21 and takes the center path. If LF<LEX, that one
word belongs to left; CMOVB at9061 selects LF. Otherwise left is exhausted and
the one word belongs to right, selected from RF. The comparison is unsigned
pointer order, justified by the admitted single nonwrapping S allocation.
9068 stores the full qword to A[10], then advances only the selected front.

Every left label is now retired exactly once, so LF=LEX. Every right label is
retired exactly once, so RF=RB+1. Guards9074/9077 and9079/907d/9080 therefore
fall through to the ordinary epilogue/RET9082..9090. There are no calls in the
admitted corridor. This proves conditional normal completion and all21 final
output words, not just a conditional first store. For arbitrary unsorted
prepared states the rank proof does not apply; no native refusal, rollback,
failure result or helper behavior is asserted.

LB may be -1 after the tenth back retirement (for example, the frozen
`right-below-left` case). This is after the final pair's memory reads and is
never indexed again. Adding one at9040 yields LEX=0. Before every pair read,
LB>=0 as proved above. An unsigned Rust back-index decrement would need
explicit wrapping or a signed relative index to avoid inventing a panic.

The guard failure call9091 resolves through RELATIVE slot576eaf8 to157a6d0;
UD2 follows at9097. The seed-unwind landing pad9099 uses imported memcpy at
GLOB_DAT slot576dfe0 and resumes unwind. Neither is interpreted transitively
or included in this normal-return proof.

## Pre-source finite witnesses and limitations

`PRE-SOURCE-FULL-ARRAY-FREEZE.json` freezes80 admitted conditional cases and4
separate safe-API refusal policy cases, before the proposed module exists.
The immutable-rank oracle is independent of the eventual imperative Rust.
Complete A21/S37, right insertion indices, ten front/back provenance triples,
center side, final cursors and logical store records are frozen. They include
both early exhaustion shapes, both center sides, all27 shifts, unsigned high
bits, duplicate boundaries and all-equal dual back provenance.

These are static-derived expectations. They are not target-run outputs, an
exhaustive proof by testing, external timestamp evidence, physical compiler
store measurements, seed reachability, exception closure or a full sort gate.
