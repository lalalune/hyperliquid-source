# Normalization and all-count packed-coefficient closure

Node #94 target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are original ELF VAs. The claimed closure is exactly the complete
146-byte normalizer `[0x565ec20,0x565ecb2)` and its complete 141-byte tail
loop `[0x565ecc0,0x565ed4d)`: 287 bytes, not the intervening/following
14/19 bytes of separately checked alignment context. Both actual FDEs and
all bytes are pinned. The normalizer's final RET is retained but unreachable
from its entry, because the preceding JMP unconditionally enters the loop.

## Domain and two entry points

The normalizer reads eight qwords from entry RSI: arrays a and b of four
little-endian limbs each. All reads must succeed and remain stable. The function
has no stores, so overlapping externally supplied snapshot descriptions are
harmless when consistent with the original bytes. This value API does not
model faults, volatile/concurrent memory, flags, stack/return control or the
custom machine ABI. Entry RDX is an arbitrary raw u64 count.

The loop may also be entered directly with arbitrary u64 X=R8, Y=R10 and
raw RDX. The direct API additionally takes R9/R11 values so that its returned
13-register projection preserves these two untouched registers. The normalizer
sets R9/R11 before entering the same loop. RDI and RSI are unchanged and are
not synthesized by the value API. There are no numeric exclusions or new
refusal cases for either entry point.

This is distinct from the published fixed 30-step function at
`[0x565f2e0,0x565f390)`: these two FDEs normalize a four-qword pair, preserve
low 31 bits, execute a variable low 32 count, wrap two biased packed coefficients
at 64 bits, and decode their halves only at the end. No fixed 30-step bytes or
its source implementation are claimed again.

## Normalization without undefined output

Let B=2^64 and L=2^31-1. The first two groups of conditional moves inspect
limb pairs at ranks 3, 2, 1 in descending order. Let h be the largest rank in
1..3 with `(a[h]|b[h])!=0`, or zero when no such rank exists.

When h>0, the selected high pair is a[h],b[h] and the following low pair
is a[h-1],b[h-1]. BSR of their nonzero OR gives
`r=floor(log2(a[h]|b[h]))`. After LEA and NEG, SHLD uses count
`k=(-r-1) mod64 = (64-bit_length(a[h]|b[h])) mod64`, in 0..63.
The paired shift result is

```
H_a = floor(((B*a[h]+a[h-1])*2^k)/B) mod B,
H_b = floor(((B*b[h]+b[h-1])*2^k)/B) mod B.
```

For k=0 SHLD leaves the destination unchanged, so this formula remains valid
without a 64-bit source shift. The Rust helper handles zero separately.

When h=0, the BSR operand is zero. Its destination RCX is architecturally
undefined, and the subsequent LEA also carries that unknown intermediate.
However ZF=1 is defined by BSR, LEA preserves flags, and the conditional moves
at `0x565ec7d/81/85` replace both high words with a0/b0 and replace RCX
with RAX=0 before NEG or either SHLD. Thus no unspecified value influences
an observable output or a shift count. The resulting H_a=a0,H_b=b0 is fully
defined, even when those low words themselves are nonzero. It would be wrong
to normalize those low words using their own leading bit or to refuse this
input as though the undefined intermediate survived.

The last masks and ORs produce

```
R9  = H_a & (B-1-L),       X = (a0 & L) | R9,
R11 = H_b & (B-1-L),       Y = (b0 & L) | R11.
```

The normalizer's unconditional tail jump then enters the complete loop. In the
h=0 case X=a0 and Y=b0. In all cases the low 31 bits are preserved while the
upper 33 bits come from the selected double-word shift. R9/R11 retain their
masked high parts throughout the loop.

## Exact single-step recurrence

Set

```
U0 = 0x7fffffff80000000,
V0 = 0x800000007fffffff,
K  = 0x7fffffff7fffffff.
```

Coefficients U,V are raw u64 words. All coefficient operations below reduce
modulo B; they are not two independently wrapping 32-bit lanes.

At each pass the target first saves old X,Y,U,V in RAX,RBX,RBP,R14.
It tentatively swaps X/Y and U/V if unsigned X<Y, forms X-Y and U-V+K,
then tests the *saved old X* parity. If old X was even, conditional moves
restore all four original values. Finally X is logically shifted right 1,
V becomes 2V-K, and EDX is decremented. Hence the exact pass is:

- For even X: `(X,Y,U,V) -> (X/2,Y,U,2V-K)`.
- For odd X with X>=Y: `((X-Y)/2,Y,U-V+K,2V-K)`, with integer floor
  division when X-Y is odd.
- For odd X with X<Y: `((Y-X)/2,X,V-U+K,2U-K)`.

All pair arithmetic uses nonnegative differences after unsigned ordering. No
oddness, coprimality, nonzero or reduced-range condition is imposed on Y.
Equal odd values take the nonswap branch and produce X'=0. Zero X follows the
even branch and remains zero, regardless of Y.

The loop is a do-while count: it executes before `SUB EDX,1`. Thus n is
low 32(raw_count) when nonzero and 2^32 otherwise. Entry high 32 bits are ignored.
Every entry executes at least one pass, so all saved final temporaries are
defined. The count reaches zero, but the epilogue subsequently overwrites RDX
with a coefficient-derived value; the returned RDX is not that zero count.

## Derived 128-pass descent bound

Define `ell(0)=0`, and `ell(z)=floor(log2(z))+1` for positive z. Initially
`P=ell(X)+ell(Y)<=128`. Consider any pass with X>0:

- If X is even, X/2 has bit length ell(X)-1 and Y is unchanged.
- If X is odd and X>=Y, `0<=(X-Y)/2<=floor(X/2)`, so the new X bit
  length is at most ell(X)-1; Y is unchanged.
- If X is odd and X<Y, `0<=(Y-X)/2<=floor(Y/2)`, so the new first
  bit length is at most ell(Y)-1 and the new second bit length is ell(X).

In every case P decreases by at least one. This includes equality, zero Y
and every parity combination. Since P is nonnegative, at most 128 passes with
nonzero X can occur. A count may end sooner; otherwise X reaches zero. This
is a universal proof, not a bound inferred from observed fixtures (whose
maximum explicit-step count happens to be 127).

## Exact stable tail and final temporaries

Once X=0, Y and U remain fixed and `V -> 2V-K mod B`. For r additional
passes,

```
V_after(r) = K + (V_before-K)*2^r mod B.
```

For r>=64 this equals K. There is no x86 masked-shift interpretation in this
mathematical power: a shift count of64 must absorb the old coefficient, not
reuse it. The Rust function branches at 64 before using a wrapping shift for
counts 0..63.

If r>0, the saved values at the *last* pass are `(0,Y,U,V_after(r-1))`.
The final coefficient is `V_after(r)`. These differ near the absorption
boundary, so returning the final V in R14 would be wrong. If no passes remain
when X first becomes zero, the preceding nonzero-X pass's saved values are
retained instead. Entry X=0 is handled by the same stable formula with r=n.
The source therefore performs at most 128 explicit pair steps and constant-time
stable-tail evaluation for all n up to2^32.

## Epilogue and full register projection

Let final packed words be U,V, and saved pre-final values be A=X_old,
C=Y_old,P=U_old,Q=V_old. The target shifts K right32 into R15=L. MOV ECX,EDX
and MOV R13D,R12D zero-extend the low 32 words before four 64-bit bias
subtractions. With each subtraction modulo B, the projection is

```
RAX=A, RBX=C, RBP=P, R14=Q,
R8=X_final, R10=Y_final,
RCX=(U>>32)-L, RDX=(U mod2^32)-L,
R12=(V mod2^32)-L, R13=(V>>32)-L,
R15=L.
```

R9/R11 are either supplied unchanged direct-entry values or the masked
normalizer high words above. All 13 reported registers are exact raw u64
values. No sign extension of the low 32 fields is justified; a high bit in
such a field is still zero-extended before subtracting L. RBX/RBP are not
restored here: these two functions do not save them, which is part of the
custom register protocol rather than an invented standard ABI.

## Independent oracle and safe implementation bounds

The frozen oracle computes normalization from two whole 256-bit integers and
a selected 128-bit prefix quotient. For coefficient evolution it composes
integer 3x3 affine matrices on `(U0,V0,K)`, reducing only when extracting
observations. Its three transition matrices are

```
even:    [[ 1, 0, 0], [0,2,-1], [0,0,1]],
odd >=:  [[ 1,-1, 1], [0,2,-1], [0,0,1]],
odd < :  [[-1, 1, 1], [2,0,-1], [0,0,1]].
```

Integer matrix composition followed by reduction modulo B is equivalent to
reducing after each coefficient operation because reduction is compatible with
addition and multiplication. The source instead uses direct wrapping-u64
coefficient updates and explicit word shifts. The stable tail is evaluated
with Python modular exponentiation in the oracle and a bounded shift/absorption
branch in Rust. Neither executes nor interprets captured instructions.

X-Y cannot underflow after the source's unsigned swap. All coefficient wraps
are explicit. The counter is positive and at most 2^32; it is decremented only
when nonzero, and `remaining-1` is evaluated only in the positive stable-tail
branch. Leading-zero calls see a nonzero selected high pair. SHLD reconstruction
uses shift 0 separately and shifts 1..63 otherwise. Every array index is 0..3.
There is no unsafe code, integer overflow trap, undefined shift or input refusal.

## Static closure and retained caller context

The full-body/FDE/CIE locks retain both functions and the complete caller
`[0x565df20,0x565e78b)`. Fifteen E8 scan hits to the normalizer are confirmed
at instruction boundaries in that caller. The only EB candidate to the loop
is the normalizer's tail at 0x565ecae. The E9 scans are empty. Caller semantics,
other callees and caller input constraints are not reconstructed or assumed.
All 80,300 RELA records are checked for naming addends and overlapping writers
to the locked bodies/padding; none match. There are no table or RIP-relative
data dependencies in the two-entry closure. This is not a complete whole-node
xref census, original source identification or component progress gate.

## Qualification provenance and a detected fixture gap

The original 6,788 cases and affine oracle were frozen before Rust. The first
qualification's `wrong_lower_limb` mutant returned exactly those expected
outputs, exposing a coverage gap: a small selected high limb at rank 2/3 with
high bits in its immediately preceding limb was not represented. Such bits
can survive the preserved-low 31 mask after a sufficiently large SHLD count.
Random high limbs usually select a small shift, which hides that contribution.

The original oracle, pre-Rust freeze and Rust source remain byte-identical.
`supplement.py` adds an explicitly post-Rust corpus covering all high-limb
bit positions 0..31, preceding-limb bits 31/32/47/63, all three nonzero ranks,
both operand sides and counts 0/1/32. Its expectations call the unchanged frozen
affine oracle. `supplemental/SUPPLEMENT-FREEZE.json` binds its timing, source
hashes and separate fixture hashes; it is not labelled pre-Rust. This repairs
the observed qualification gap without changing the independently established
relation or concealing the original ineffective control.

The initial validator kept native output only in memory until completion, so
that unsuccessful invocation's native stdout was unavailable afterward. Its
original stdout/stderr and validator source are retained, together with an
explicitly labelled replay of the unchanged still-existing mutant binary whose
output equals the original expectations. That replay is not represented as
original-run raw provenance. The packet-local validator now saves native streams
when a control is ineffective as well as when a command fails. Final successful
qualification retains every original command stream without this limitation.

A concrete new witness uses a=[0x1234567,0x100000000,1,0],
b=[0x7654321,0,0,0] and count 1. Rank 2 selects shift 63. Correct R9 is
0x8000000080000000: bit 32 of the immediately preceding limb becomes bit 31.
Using a0 instead of a1 gives R9=0x8000000000000000. R9 survives the whole
loop unchanged, so this distinction is directly observable. The final complete
qualification detects 588 mismatches for this mutant, including this boundary
class, while preserving the original failed-control evidence.
