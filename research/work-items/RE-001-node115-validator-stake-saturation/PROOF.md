# Conditional arithmetic and index proofs

This is a manual proof of relations extracted from the pinned instruction spans.
It is not a proof of the whole ELF, machine-checked execution, or an implementation.
All weights below are unsigned 64-bit integers. Let `U = 2^64 - 1`.

## The three accumulation sites

The keyed fold uses ADD at `0x4e44c65`, then conditional moves at `0x4e44c73`
and `0x4e44c77`. The flat all-weight route uses ADD at `0x4e40729`, then CMOVB
at `0x4e40730` and `0x4e40738`. The tree accumulation route uses ADD at
`0x4e4078a` and CMOVB at `0x4e40792` and `0x4e40796`.

In each sequence, intervening MOV or LEA instructions preserve the ADD carry.
On no carry, the result is exactly `a+b <= U`. On carry, the two conditional
moves select the register loaded with all ones. Thus every update is
`min(U,a+b)`. By induction from zero and nonnegative weights,

```
fold(w[0..n]) = min(U, sum(w[0..n]))
```

for every finite normally completed stream. The induction step uses
`min(U,min(U,x)+w) = min(U,x+w)`. Once saturated, later zero and nonzero
weights preserve U. The loop nevertheless keeps visiting entries; saturation
is not a short-circuit and cannot suppress later helper effects or failures.

The selected-key fold reaches the update only after finding a weight. Every
missing-key branch goes back to the iterator while retaining its saved sum.
Under a stable map and normally terminating iterator, it folds the weights of
found key occurrences; absent occurrences contribute nothing. Upstream
uniqueness is not assumed or proved. Tree traversal and lookup results are
explicit validity/helper premises, not replaced by synthetic callback outputs.

## Wide predicate on the returned sums

Let B and S be the two u64 fold returns. The predicate's final sequence supplies
`2*S` as `(S>>63, (2*S) mod 2^64)` and `3*B` as the MUL high/low pair. The low
CMP supplies borrow `b = left_low < right_low`; SBB sets carry exactly when
`left_high < right_high+b`. The left high limb is at most 1, the right at most
2, so adding b cannot overflow. SETB therefore means `2*S < 3*B`, strictly.

The products fit below `2^66`. Equality, including B=S=0 and B=2,S=3, is false.
B=S=U is true and requires keeping the high limbs. This common wide comparison
was previously analyzed in #987/#1928; it is independently rebound to this
predicate, not claimed as a new arithmetic technique.

Saturation must occur before comparing. For raw streams selected `[U]` and
all `[U,U]`, the observed sums are B=S=U, so the predicate is true. Comparing
unbounded raw sums instead would give `4*U < 3*U`, false. This example isolates
the arithmetic; it does not assert that such weights occur on a live network.
A checked-overflow implementation would also differ by rejecting the second
sum. Neither the checked path nor an unbounded ratio may substitute for this
observed saturating route without additional input bounds.

## Flat spans and lookup bounds are distinct

For the total-span builder, assume `0<c<2^63`, `0<=h<2*c`, `0<=n<=c`, and
valid nonwrapping backing storage. Normalize `s=h-c` when h>=c, otherwise s=h.
Then `0<=s<c`. If n<=c-s, the spans are `[s,s+n)` and empty; otherwise they are
`[s,c)` and `[0,n-(c-s))`. Their concatenation has n indices and equals
`(h+i) mod c` for `0<=i<n`. For n=0, the observed two spans are empty at index0.
Stride32 and weight offset24 come from the pinned instructions.

The post-lookup branch has a **stronger canonical-head premise**, `0<=h<c`.
It first rejects status low-bit 1 or i>=n. With `i<n<=c`, `h+i<2*c`, so one
conditional subtraction yields `(h+i) mod c` and the weight address is
`data+32*((h+i) mod c)+24`. Extending this theorem to h<2*c would be unsound:
it could require two subtractions. No malformed representation is declared safe.

## Counterfactuals and finite checks

`relations.py` checks the finite corpus recorded in `relations.json`. The
expected saturated sum uses Python's unbounded sum followed by a clamp, whereas
the local update model uses carry/wrapped-word arithmetic. The wide check uses
separate limbs and borrow against Python's exact inequality. Index spans are
checked against a modulo-index sequence, and lookup branches against low-bit,
unsigned-bound and modulo formulas.

For each of the three final CMOVB instructions, a real opcode byte is changed
from 0x42 to 0x43 (CMOVAE). The first conditional move is left intact. With
ADD carry set, the changed final move no longer installs the clamp: `[U,1]`
then produces zero rather than U in the corresponding algebraic counterfactual.
The mutated image is also rejected by the instruction obligation checker with
whole-image hashes, body hashes and native exports bypassed. No changed ELF is
executed or emulated. The finite checks support regression detection; the
manual arguments above supply the stated all-domain relations under their
explicit premises.
