# Conditional j9 closure and n21 phase premises

Read-only follow-on to #1524 and #1455. Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No generalized Rust, tracked edit, captured execution or publication exists.

## Whole selected j9 branch

At the first j8 completion join `0x4918f06`, RSI=8 and RAX=64.
The next INC/add8 give RSI=9/RAX=72. R12 is h=floor(n/2), hence10..16;
RCX=8 and RDX=n-h survived the whole left step. JE at `0x4918f10` is
therefore not taken, so every admitted count21..32 enters j9 at `0x4918f12`.

This entry loads the full qword A[9], stores it first to S[9], and reads S[8].
Unsigned JAE at `0x4918f22` joins completion immediately on equality/greater.
Otherwise R8=72 and the predecessor shift begins at `0x4918f30`.
After each shift, offset8 is tested before any lower read. Larger offsets
load offset-16 and subtract8; unsigned JB alone repeats the shift.
The possible offsets are72,64,56,48,40,32,24,16,8. Thus at most9 shifts occur;
the front case reaches S[0] without an S[-1] read. The final x store rejoins
`0x4918f06`. RAX/RSI are unchanged inside the local step.

For current prefix q0..q8 and y=A[9], the exact result moves only its maximal
contiguous suffix strictly greater than y right, then inserts y. Equality
stops. It reads only within S[0..9) and writes only within S[0..10).
The chosen path can write a subset of that range. A and all other scratch
remain unchanged, including the n21 right-prefix region beginning at S[10].
This relation permits an unsorted prefix; it does not establish sorting.

There is no call in the selected branch. It terminates for every raw qword
prefix/y under valid stable nonwrapping A[9], S[0..10) and callee-frame
premises. A/S are disjoint from each other and the live spills/return
machinery; scratch in an ancestor frame is permitted. Arrival after ordinary
seed returns remains a premise, not recovered seed behavior or whole-call
state reachability.

At completion, INC/add8 produce RSI=10/RAX=80. The comparison is against h,
not n-h. Within21..32, only n21 has h=10, so only n21 takes the left-exit JE
immediately after j9. Counts22..32 enter left j10; their later phases remain
outside this closure.

## n21 right-entry and conditional merge-front

At `0x4918f4d`, RAX changes role from numeric byte offset to pointer S+80.
RSI is then replaced by source pointer A+80; RCX remains the seeded index8,
RDI becomes byte offset64, and RDX remains right length11. The JAE skip-right
test8>=11 is false. First right source/destination are A[18]/S[18], with
preceding scratch S[17]. Both value loads/stores and comparisons are qword
width; the value gates are unsigned JAE/JB.

For n21 only, the right-loop control/coordinate premises close as follows:
RCX takes8,9,10; RDI takes64,72,80; source indices are18,19,20. The same
front-guard/decrement8 argument bounds each inner scan, with no call and no
negative prefix read. After the third completed step, RCX becomes11 and JE
at `0x4918f80` reaches `0x4918fbd`. This establishes conditional control
reachability and readable/writable extents; a complete right-array value
transformation is not reconstructed here.

The setup stores n in the live stack frame and establishes, before
`0x4918fe0`:

| Role | n21 state |
| --- | --- |
| right-front RAX | S+80 |
| left-front RSI | S |
| right-back RCX | S+160 |
| left-back RDX | S+72 |
| output-front RDI |0|
| output-back R8 |20|
| pair count R12 |10|
| output base R15 | A |

The independently decoded `0x4918fe0..0x4919018` corridor is56bytes/16
instructions. It reads right-front S[10] and left-front S[0]. CMP at
`0x4918fec` and CMOVB at `0x4918ff7` retain the unsigned smaller value in
R10; equality retains the left. Back-side preparation also reads S[20]/S[9]
but does not change R10. The first full-qword store at `0x4919014` writes
that value to A[0]. This is conditional unsigned min(S[0],S[10]), not a
global minimum. For left `[9,0,8,1,7,2,6,3,5,5]` and right
`[8,10,11,12,13,14,15,16,17,18,19]`, it yields8 while the scratch minimum
is0. Sorted halves or an equivalent head-minimum invariant remain missing.

## Frozen and executed controls

Original `J9-TRANSITION-FREEZE.json` remains unchanged, SHA-256
`adc217c39692223e24f57ea9eb63fbd9c0a833e34ec3103c40885533f9e8d49b`.
It contains5 literal count boundaries,5 j9 word states and6 proposed static
controls, all before generalized Rust.

Those6 controls were subsequently **executed** as individual inert0600 ELF
copies, with both native decoders and whole-file/window guards bypassed:
wrong left length register, inverted left exit, byte increment16, right base
scale4, wrong right admission condition and merge-back n instead of n-1.
Each fails its intended static operand/CFG property. This is recorded in
`J9-STATIC-VALIDATION.json`, SHA-256
`fc098b44c3014c2c7f294dfab4e86f655572795b4eaef33ee5120167b5c69fbe`.
The224-byte/59-instruction expanded envelope agrees between GNU/LLVM and
still matches the authenticated owner/FDE. These are finite static checks,
not execution of mutated captures or a complete x86 proof.

The additional conditional n21 entry/front cases and explicit missing
head-minimum premise are frozen in `N21-MERGE-FRONT-PREMISES.json`, SHA-256
`3181bd1e3918bef846e4a7691bf8b5ba958702f4a2a347557d711e55461d3f5c`.

Seed output semantics, the n22..32 left continuation/right phases, complete
right-array effects, back store, later merge/center/crossover/failure and
original ABI/alias acceptance remain partial. A j9 front case can shift all9
prefix words, so applying the existing fixed9-word j8 API to a sliding suffix
would incorrectly exclude S[0]. No generalized implementation is proposed
before independent review of these native facts and frozen expectations.
