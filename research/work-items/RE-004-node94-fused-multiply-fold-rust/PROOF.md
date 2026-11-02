# Raw prepared-register fused multiplication and four folds

The scope is the complete 786-byte, 231-instruction leaf
`[0x565d440,0x565d752)` in node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The two dispatch wrappers are call-site context only. Their global feature
test, alternate entries, native ABI and full behavior are not reconstructed.

## Domain and independent entry values

Let B=2^64. The entry register values below are independent members of `[0,B)`:

| Symbol | Incoming register |
| --- | --- |
| u | RAX |
| z0,z1 | R9,R10 |
| v1,v2,v3 | R14,R12,RBP |
| w | R15 |
| f | R8 |

Read four little-endian qwords through incoming RSI as integer A in `[0,B^4)`.
Read b1,b2,b3 at incoming RBX+8,+16,+24. **RBX+0 is never read.** Read four
qwords through incoming RCX as integer M in `[0,B^4)`. The original slot
`[entry RSP+8]` supplies an output address D. It is a data value loaded by the
body, not an additional recovered machine argument. The safe value API takes
that value explicitly and never dereferences a native stack or pointer.

No relation such as u=w, a prepared first product, sign extension, odd M,
nonzero M, or a Montgomery-inverse condition on f is assumed. Values supplied
by the two observed wrappers form a subset of this domain. No quantity names
or cryptographic identity are inferred from the arithmetic shape.

Original correspondence assumes stable ordinary memory, successful reached
accesses and a successful return. Stack/control storage, including the supplied
slot and return address, is disjoint from the adapter's data image. All aliases
among the represented A, later-B, M and output bytes are allowed. Exceptions,
MMIO, volatile/concurrent observations, flags, CET and native ABI behavior are
outside this value/image projection.

## Whole-integer relation

The initial five-word accumulator is

`T0 = z0 + B*(z1+u*v1) + B^2*w*v2 + B^3*w*v3`.

It is less than B^5 for all raw register inputs. In particular the separate
roles of u and w must not be silently equated. The first product uses u*v1;
the following two use w*v2 and w*v3.

For any nonnegative integer T below B^6, define

`l = T mod B`, `q = (l*f) mod B`, `p = l+q*(M mod B)`,

`e = ((p mod B)+floor(p/B)) mod B`,

`F(T) = floor(T/B)+q*floor(M/B)+e`.

This fold retains the low remainder, adds it to the high half, and discards
overflow of that sum. It is not ordinary division by B unless additional
conditions happen to make it so. The reconstruction imposes no such condition.

For j=1,2,3, in order:

`Tj = F((T(j-1)+B*A*bj) mod B^6)`.

Then `S=F(T3)`. Let `E=(S−M) mod B^5`. The selected value is S when S<M,
otherwise E. The output is its low four words. This is one extended-width
conditional subtraction, not a claim that the result is a canonical remainder.

Both kinds of lost carry are material. For l=1, f=B−1 and M mod B=B−1,
p=B^2−2B+2, so its low/high sum is B and e=0. Keeping that sum as B is wrong.
For all eight prepared values equal to B−1, A=M=B^4−1 and all bj=B−1, the first
two interleaved results are `T1=B^5−1` and `T2=B^5+B^3−2`. The next product
addition is `B^6+B^3−B^2+B−2`, which crosses B^6. The target discards this
384-bit overflow. An unbounded accumulator would change subsequent folds.

## Full-body derivation and widths

The first three MUL/ADD/ADC groups at 0x565d444..0x565d46e construct T0's
words1..4 while leaving z0 in R9. The initial R10 participates in the first
low-half addition; it is not inferred from a previous product. XOR R14,R14
initializes the sixth word to zero. Maximum inputs give

`T0 ≤ B^5−B^4+B−1 < B^5`.

The blocks beginning at 0x565d482, 0x565d540 and 0x565d5fe add b1*A, b2*A and
b3*A respectively at one-word offset. Four unsigned products and carry chains
add exactly B*A*bj. Each accumulator has six words. Carry out of its highest
word is discarded before a subsequent XOR/MUL resets flags. Hence the explicit
modulo B^6 at every interleaved addition is required for the raw entry domain.

Each fold multiplier is formed with the low64 result of IMUL. Signed and
unsigned multiplication have the same low64 residue; f is an arbitrary word.
The multiplier is computed before the adjacent B*A*bj addition, but that
addition does not affect the low word. It therefore equals the q defined above.

For the low product, ADD adds its low half to l. ADC then adds its high half
and that ADD's carry to the resulting low word. The outcome is exactly e.
The ADC's final carry is not forwarded to the next accumulator word: a new
MUL and ADD replace the relevant flags. Subsequent products q*m1, q*m2, q*m3
are added to the next three accumulator words with e as initial carry. The
remaining high words receive the last multiplication carry. Dropping the old
low word gives precisely F(T).

The first three folds occupy different rotating register groups, but each has
this same complete six-word relation. The final fold begins at 0x565d6b1 and
has no additional b4 product. It uses the prior T3, loads the supplied D into
RSI, and leaves a five-word value S before subtraction.

For every T<B^6, q≤B−1, floor(M/B)≤B^3−1 and e≤B−1 imply

`F(T) ≤ B^5+B^4−B^3−1 < B^6`.

Applying this bound to T3 gives

`S ≤ (B^4+B^3−B^2−1)+(B^4−B^3−B+1)+(B−1)`

`  = 2*B^4−B^2−1 < 2*B^4`.

Thus S's fifth word is 0 or 1, and any sixth word is zero. This is a derived
bound for all raw prepared inputs, not a reduction or canonical-input premise.
The final four SUB/SBBs subtract M, then `SBB R10,0` subtracts the low-word
borrow from S's fifth word. Its CF indicates S<M. CMOVB restores the saved
low words only on that borrow. The fifth difference word itself is not restored.
Four stores write the selected low256 bits at D,D+8,D+16,D+24.

Every Rust product accumulation fits u128: for word x,y, an existing word and
carry each at most B−1,

`x*y+word+carry ≤ (B−1)^2+2*(B−1) = B^2−1`.

The initial products need at most one added word. The low fold product satisfies
p≤B^2−B. Explicit u64 wrapping operations implement the two documented lost
carries; no signed overflow, overshift or undefined operation is used. The
six-word arrays have fixed bounds, with three interleaved steps and one final
step. The library allocates nothing and forbids unsafe code.

## All modified general-purpose registers

Let q3,e3 be q,e for the last fold and e2 the e of the third interleaved fold.
Write S0..S3 for S's low words and O0..O3 for the selected output words.
Define

`H = floor(((floor(T3/B) mod B^3)+q3*floor(M/B)+e3)/B^3)`.

H is the final product carry after adding the old accumulator limb and the
preceding product carry; it is not merely the high half of the raw final MUL.
The numerator is at most B^4−1, so H is a u64. The full final registers are:

| Register | Value |
| --- | --- |
| RAX | S0, saved before conditional subtraction |
| RDX | H |
| RBX | S1, saved before conditional subtraction |
| RBP | S3, saved before conditional subtraction |
| RDI | e2, from the third interleaved fold |
| RSI | D, the supplied stack-slot value |
| R9 | O3 |
| R10 | floor(E/B^4), including B−1 on borrow |
| R11 | q3 |
| R12 | S2, saved before conditional subtraction |
| R13,R14,R15 | O0,O1,O2 |

The last fold uses R12, not RDI, as its low-product accumulator. RDI therefore
retains e2. The final MUL's high half receives two carry corrections before
being added into the next word, so exposing an uncorrected high half as RDX
would be wrong. RAX is overwritten with the saved S0 before the final SUBs;
it is not the selected output O0 when subtraction succeeds. R8 and RCX retain
their incoming factor/pointer values and are outside the modified-register
record. RET's stack/control effects and flags are excluded.

## Reads, aliases and the finite-image adapter

The complete leaf has 40 memory instructions: 12 A-word reads, three later-B
reads, 20 M-word reads (including final subtraction), the supplied stack-slot
read, and four stores. There are no stores until all input and stack-slot loads
have finished. Stable repeated reads can therefore be represented by immutable
A/B/M snapshots, even when those data roles or output storage overlap. All
output words are computed before the first store. Every other image byte stays
unchanged, and no alignment premise is added.

The source `Prepared` fields are the eight independent raw register values.
`evaluate` takes the successful data observations plus D explicitly. A caller
must satisfy the original successful-access/control premises to interpret this
as a target execution projection. It does not pretend to dereference RSP or
reproduce either dispatch wrapper.

`apply_image` supplies one finite image mapping byte i to base+i with exclusive
end≤2^64. A and M require 32 contiguous bytes at their addresses. Later-B requires
24 bytes starting at (B-address+8) mod2^64; no byte at B-address itself is needed.
Each span is admitted by checked subtraction, usize conversion and checked end.
Three separate original later-B field addresses have the same represented bytes
as that contiguous span on this one-interval domain; a wrap between its required
bytes cannot fit in one nonwrapping finite interval. Output requires 32 bytes at D.

The represented source and destination data may alias arbitrarily. Original
stack/control storage must remain disjoint and successfully readable; the
separately supplied D is its value. The API does not invent native pointer
provenance or imply a native stack read. Missing required spans or a wrapping
image produce the new `None` refusal. No write occurs on refusal. Output-span
validation may precede reads in the safe API; no original fault/access ordering
on invalid inputs is claimed.

## Static and qualification closure

The complete leaf, actual unique FDE, complete shared CIE and 14 separate NOP
alignment bytes are bound. There is no internal branch, call, RIP-relative
operand or static table. The one explicit stack-slot load is retained, not
replaced by a guessed callback or helper stub.

E8 scanning and full caller decoding establish exactly two direct candidates,
at 0x565d383 in `[0x565d340,0x565d3ad)` and 0x565d406 in
`[0x565d3c0,0x565d430)`. Their complete bodies/FDEs are retained only to qualify
these boundaries. E9/EB scans find none. All 80,300 RELA records are checked for
naming addends and full-width overlapping writers to retained bodies/padding.
This is not a complete indirect-reference census or wrapper reconstruction.

The independent oracle was frozen before Rust. It constructs T0 by a whole
integer polynomial, uses whole-product additions modulo 2^384, and applies the
quotient/remainder fold equations. It computes H as a three-word prefix quotient,
not a simulated carry chain. Rust separately uses bounded word arrays and u128
multiply-accumulate operations. The frozen oracle imports no Rust and executes
no captured instruction sequence or emulator.

Finite native vectors complement the all-domain proof. They include independent
prepared-register bits, every data-word bit rank, arbitrary factors/moduli,
actual six-word wrapping and fold-carry loss, both subtraction paths, fifth-word
one, consistent-wrapper subsets, data aliases and missing-span refusals. Only
newly authored Rust executes. Original compiled-byte equality, native ABI,
whole-node behavior and any component-completion gate remain unclaimed.
