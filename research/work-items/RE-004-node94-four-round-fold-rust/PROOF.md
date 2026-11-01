# Complete four-round relation

Target: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are original ELF virtual addresses before load bias. The claim is
exactly the 388-byte leaf `[0x565d8a0,0x565da24)`, including its `repz ret`.
The independent FDE covers those exact bytes. The adjacent 28 alignment bytes
are checked as context, not part of the function.

## Inputs and observation boundary

Let `B=2^64`. The four qwords loaded from entry RSI at offsets 0, 8, 16,
24 are `a[0..4]`; the qwords read from entry RBX at those same offsets are
`m[0..4]`; entry RCX is `c`. All nine words may be arbitrary elements of
`[0,B)`. The source uses value snapshots. Correspondence to original memory
requires all 20 reads to succeed and remain stable, with valid address
formation. The two input windows may overlap: this leaf does not write memory.
There is no claim about faults, volatile or concurrently changing storage,
stack/return control, flags, or the custom calling convention. The nine named
written general-purpose registers are returned explicitly. Other general-purpose
registers, except instruction/stack control, are unchanged by the leaf; their
entry values need not be supplied to the value API.

Neither a modulus interpretation, an odd operand, a multiplicative inverse,
nor a reduced input is required or asserted. In particular, replacing the
first-word operation with the carry used by an ordinary cancellation reduction
would be incorrect on the admitted arbitrary-input domain.

## One round

Encode the current four words as `A = sum(a[j] B^j)` and operand as
`M = sum(m[j] B^j)`. Define

```
q = (a[0] c) mod B
p = a[0] + q m[0]
f = ((p mod B) + floor(p/B)) mod B
A' = floor(A/B) + q floor(M/B) + f.
```

The low product of signed two-operand IMUL is multiplication modulo `B`,
so the expression for `q` holds for every input bit pattern. The subsequent
one-operand MUL operations are unsigned full 128-bit products.

For the first word, MUL gives low `l` and high `h` for `q*m[0]`.
ADD replaces the accumulator's low word by `(a[0]+l) mod B` and sets
`k=floor((a[0]+l)/B)`. MOV preserves flags. ADC then adds `h+k` to that
**already replaced** low word. Since `h+k=floor(p/B)`, its result is `f`.
The carry from this ADC is discarded: the next MUL overwrites the flags.
It must not be forwarded as an extra high word.

Each remaining word `j=1,2,3` computes

```
s = q*m[j] + a[j] + carry
next[j-1] = s mod B
carry = floor(s/B)
```

with initial `carry=f`, then `next[3]=carry`. The target performs the
three-term sum as two low-word ADDs, each followed by `ADC 0` into the
product high word. MOVs and the interleaved next-round IMUL do not break a
live carry chain: the IMUL occurs before the next ADD establishes a new
carry. These two carry increments give exactly the quotient of `s/B`.

All arithmetic used by the Rust u128 sums is representable:
`p <= (B-1)^2+(B-1)=B^2-B`, and
`s <= (B-1)^2+2(B-1)=B^2-1`. The second bound also prevents either
intermediate high-word carry adjustment from wrapping: both increments are
nonnegative and their final result is below `B`. The fold uses explicit
wrapping u64 addition; shifts are always exactly 64 on u128 values.

The whole next value remains four words because

```
0 <= A' <= (B^3-1) + (B-1)(B^3-1) + (B-1) = B^4-1.
```

Thus the same proof applies inductively to all four rounds. There are no
rejected numeric inputs or undefined shifts, including zero and all-ones words.

## Independent expectation formulation

The frozen Python oracle does not perform the limb carry convolution. In each
round it calculates the unrestricted whole integer `T=A+q*M`, then

```
r = T mod B
h = floor(((A mod B) + q*(M mod B))/B)
d = floor((r+h)/B)
A' = floor(T/B) + r - B*d.
```

Here `r=p mod B`, `h=floor(p/B)`, and `d` is either zero or one.
Expanding `floor(T/B)` gives
`floor(A/B)+q*floor(M/B)+h`; therefore `h+r-B*d=f` establishes the
same relation without register simulation or a per-limb carry chain. The
oracle was frozen before the Rust directory existed. Its digest, UTC timestamp,
input and expected-output hashes, and static admission facts are recorded in
`frozen/ORACLE-FREEZE.json`.

A concrete counterexample to dropping the low fold uses
`a=[1,0,0,0]`, `m=[B-1,0,0,0]`, `c=B-1`.
Then `p=B^2-2B+2`, so low 2 plus high `B-2` wraps to zero.
The first next accumulator is zero and remains zero for all remaining rounds.
This is ordinary admitted behavior, not a special refusal or assumed inverse.

## Pipeline and final register values

Number rounds and multipliers from zero. The accumulator locations below
account for the target calculating the following multiplier early, after its
low word is settled but before the current round's upper words are complete.
No subsequent upper-word operation changes that settled low word.

| Point | Conceptual accumulator, low to high | Saved next multiplier |
|---|---|---|
| Entry loads | RAX, R10, R11, R12 | none |
| End round 0 | R14, R11, R12, R13 | R10 = q1 |
| End round 1 | R15, R12, R13, R14 | R11 = q2 |
| End round 2 | R9, R13, R14, R15 | R12 = q3 |
| End round 3 | R13, R14, R15, R9 | previous multipliers remain |

R9 initially holds q0 and is later reused; q0 is not a final register result.
The four fold ADCs are at `0x565d8c6`, `0x565d921`, `0x565d97c`,
`0x565d9d7`. The coefficient IMULs are at `0x565d8b6`, `0x565d8e8`,
`0x565d943`, `0x565d99e`.

Let the final four words be `v0,v1,v2,v3`. The MOV at `0x565da11`
sets RAX to R13=v0 after the final MUL has consumed its input. The remaining
ADCs only finish RDX=v3; the MOV at `0x565da1f` copies it into R9.
The exact reported tuple is therefore

```
(RAX,RDX,R9,R10,R11,R12,R13,R14,R15)
= (v0,v3,v3,q1,q2,q3,v0,v1,v2).
```

There is no memory destination, external callee, embedded arithmetic table,
RIP-relative load, indirect transfer, or branch in the leaf. All memory
operands are the four initial MOV loads and sixteen MUL loads specified above.
All RELA records are scanned for overlapping writers to the complete leaf,
both retained caller bodies, and alignment context, and for addends naming
the leaf entry. None are present in the pinned image. This is a bounded static
closure, not a claim of a complete whole-program xref census.

## Caller context is separate

Two incoming E8 patterns are confirmed at instruction boundaries in their
complete FDEs: `0x565d785` inside `[0x565d760,0x565d7e6)` and
`0x565d825` inside `[0x565d800,0x565d8a0)`. Both move entry RDX to
RBX before the direct call and save registers used by
this custom register protocol. They also branch to alternative implementations
when bit zero of a global dword is set. Their post-call arithmetic and stores, alternate
paths, memory-domain validation and coefficient provenance are outside this
leaf's claim. No all-callers invariant or mathematical operand meaning is
inferred from these two contexts.
