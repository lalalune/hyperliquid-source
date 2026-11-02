# Field interpretation and its domain

This argument qualifies the independently decoded native equations from
`foundation-multi-limb-multiply-accumulate-94`. It neither executes target
instructions nor substitutes a mathematical model for the raw source-build
comparison.

Let `B=2^52`, `C=2^32+977`, `p=2^256-C`, and represent the five input words
as the integer `N=sum(a[i]*B^i, i=0..4)`. The public `field_5x52.h` defines
this representation modulo `p` and gives the magnitude constraints below.
The selected `fe_impl_normalize_weak` source has the same mask/carry equations
as the target, now also checked by a complete 123-byte compiled comparison.

For a magnitude `m` with `0<=m<=32`, assume:

```
0 <= a[i] <= 2*m*(B-1)       for i=0..3
0 <= a[4] <= 2*m*(2^48-1)
```

These are explicit source-contract assumptions. They are not recovered
preconditions proved at any of the three binary caller sites.

Write `a[4] = x*2^48 + h`, where `0<=h<2^48`. Then `x<=63`. Before
propagating carries, replacing the high word with `h` and adding `x*C` to
word zero changes the represented integer by exactly:

```
-x*2^48*B^4 + x*C = -x*(2^256-C) = -x*p.
```

This mathematical calculation agrees with the machine's low-word arithmetic
throughout the assumed domain. In fact `a[0] <= 64*(B-1)` and
`x*C < 2^39`, so their sum is less than `2^59`, far below `2^64`.
Because `x*C<B`, the first sum is below `65*B`, and its carry is at most
64. Each subsequent sum is at most
`64*(B-1)+64=64*B`, so all subsequent carries are also at most 64 and no
64-bit addition wraps. Splitting each sum into its low 52 bits and its
carry changes no represented value. The final high word is at most
`2^48-1+64`, below `2^49`.

Consequently, for every input in this domain:

```
N(output) = N(input) - (a[4] >> 48)*p
N(output) congruent to N(input) modulo p
output[0..3] < 2^52
output[4] < 2^49
```

This is **weak** normalization. For the valid magnitude-one input that
represents exactly `p`, no high-word fold or carry occurs, so the output is
still `p`, not its canonical residue zero. Thus it is incorrect to replace
this helper with a full reduction returning a unique integer in `0..p-1`.

The magnitude restriction is necessary for this congruence argument. For
`[2^64-1,0,0,0,2^48]`, the first machine addition wraps before the 52-bit
carry is extracted. The native/Rust recurrence outputs `[C-1,0,0,0,0]`.
The input's residue is `2^64+C-1`, so the output differs by `2^64` modulo
`p`. This does not contradict the existing all-u64 Rust reconstruction;
that implementation preserves the wrapping arithmetic on the larger domain.
It does rule out extending the source-level field interpretation to every
arbitrary five-u64 input without checking its assumptions.

`numeric-controls.json` retains 160 labeled magnitude/corner cases, the
noncanonical-prime witness and this out-of-contract overflow counterexample.
Those finite checks support this argument; they are not presented as an
exhaustive test or captured execution.

`prove.py` additionally admits the full target and pinned public source,
then checks the fixed-width native recurrence against this field identity.
Z3 4.15.4 returns UNSAT for any identity or output-bound violation under the
largest allowed magnitude bounds, which include every smaller magnitude's
domain. Removing those premises returns SAT. The returned counterexample
is replayed with ordinary unbounded Python integers. The 320-bit embeddings
are exact: every five-u64 input representation and `x*p` are below `2^273`,
and `N(input)-x*p` is nonnegative because `N(input)>=x*2^256`. No wrap in
the proof embedding can conceal an integer difference.
