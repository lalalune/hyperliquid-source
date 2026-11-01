# Explicit correction to the frozen source proof

Read this together with `SOURCE-PROOF.md`. Its division paragraph incorrectly
states `-52 <= r <= 52` for `r=floor(log2(a/b))`. The exact specialized range
is **`-53 <= r <= 0`**. This correction was identified in independent peer
review after the source freeze and before any production compilation.

The nonzero positive rounded integer length is normal, so its significand b
always has53 bits. The nonzero finite sum's significand a has A bits, where
`1 <= A <= 53`. The shifted comparison in production computes either
`r=A-53` or `r=A-54`; hence `A-54 <= r <= A-53`, and the global specialized
range follows. The lower endpoint is attained by a=1 and count3: the rounded
length is exactly3, with b=`3*2^51`, giving `floor(log2(1/b))=-53`.
For example, the supplied sequence of raw words `[1,0,0]` has this sum/count
relation. This is a mathematical witness, not a captured execution claim.

The production code already computes-53 through its exact shifted comparison;
it contains no assertion or branch imposing the erroneous prose bound. The
nonnegative-shift numerator proof is unchanged:
`A+s <= A+52-r <= 106`. Subnormal quantum selection can only reduce s.
The quotient/remainder rounding, source formula, public contract, client,
build harness, oracle, corpus and expected outputs are unchanged.

The original proof and `SOURCE-FREEZE.json` remain byte-for-byte historical
records. `SOURCE-PROOF-AMENDMENT.json` binds their hashes and this addendum.
Subsequent implementation/review summaries must link this correction alongside
the original proof. It does not authorize compilation; the separate exact
coordinator source/build gate is still required.
