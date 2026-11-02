# Canonical field result of the admitted node115 equations

This proof concerns the complete 259-byte bodies at ELF VAs
`0x631d630..0x631d733` and `0x632c130..0x632c233`, exclusively in node #115
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
They are byte-identical to each other and to the scoped public-source build.
No captured or compiled code is executed.

## Native equations and their interpretation

Let `B=2^52`, `L=2^48`, `C=2^32+977`, `p=2^256-C`, and
`N(a)=a0+B*a1+B^2*a2+B^3*a3+B^4*a4`.
Every addition/multiplication in the native projection is modulo `2^64`;
right shifts are unsigned. Write `wrap(t)=t mod 2^64`.

The first pass computes:

```text
h  = a4 >> 48
t0 = wrap(a0 + h*C);          w0 = t0 & (B-1)
t1 = wrap(a1 + (t0 >> 52));   w1 = t1 & (B-1)
t2 = wrap(a2 + (t1 >> 52));   w2 = t2 & (B-1)
t3 = wrap(a3 + (t2 >> 52));   w3 = t3 & (B-1)
w4 = (a4 & (L-1)) + (t3 >> 52)
```

The final reduction selector is:

```text
x = (w4 >> 48) OR
    ((w4 == L-1) AND ((w1 & w2 & w3) == B-1) AND (w0 >= B-C))
```

In the native instructions, the last comparison is the unsigned condition
`B-C-1 < w0` (`cmp` followed by `setb`). These conditions are equivalent.
The native coefficient is `(-x) & C`; since `x` is Boolean it equals `x*C`.
The second pass computes:

```text
s0 = wrap(w0 + ((-x) & C));   o0 = s0 & (B-1)
s1 = wrap(w1 + (s0 >> 52));   o1 = s1 & (B-1)
s2 = wrap(w2 + (s1 >> 52));   o2 = s2 & (B-1)
s3 = wrap(w3 + (s2 >> 52));   o3 = s3 & (B-1)
o4 = (w4 + (s3 >> 52)) & (L-1)
```

The raw disassembly in `observed/` provides the complete instruction basis.
The source correspondence supplies an additional reviewed interpretation.
The solver does not formally decode x86 or prove compiler correctness.

## Bounded congruence and canonical range

Assume unsigned inputs with `a0..a3 <= 64*(B-1)` and
`a4 <= 64*(L-1)`. This includes the public representation's magnitude
contracts through magnitude 32; it does not establish any caller invariant.

Then `h<=63`. The initial sum is at most `64*(B-1)+63*C < 65*B`,
because `63*C < B`. Its carry is at most 64. Each following sum is at most
`64*(B-1)+64=64*B`, so every carry is at most 64 and no u64 addition wraps.
Thus `w0..w3 < B` and `w4 <= L+63`.

Ordinary positional carry propagation gives the exact integer equality:

```text
W = N(w) = N(a) - h*2^256 + h*C = N(a) - h*p.
```

The bounds also give `0<=W<2^256+64*B^4<2*p`. The field prime has
base-`B` digits `[B-C, B-1, B-1, B-1, L-1]`. If `w4>=L`, then `W>=2^256>p`
and `w4>>48=1`. Otherwise lexicographic comparison with these prime digits
is exactly the Boolean clause in the selector. Since `w1..w3` are each
52-bit words, their AND is `B-1` precisely when all three are `B-1`.
Consequently `x` is exactly the indicator `W>=p`.

The second pass has `s0 < B+C < 2*B`; subsequent sums are at most `B`.
They do not wrap at 64 bits. If `x=0`, then `W<p<2^256`, no bit 256 is
removed, and `N(o)=W`. If `x=1`, `p<=W<2*p` implies
`2^256<=W+C<2^257`; masking the high word removes exactly `2^256`.
Therefore `N(o)=W+C-2^256=W-p`.

Together:

```text
N(o) = N(a) - (h+x)*p
0 <= N(o) < p
```

This is the unique canonical residue of `N(a)` modulo `p`. The exact-prime
input yields zero, unlike a single weak-normalization carry pass.

## What remains true outside the congruence domain

For arbitrary u64 inputs, the wrapping first pass still produces
`w0..w3<B` and `w4<=L-1+4095`. Hence `W<2^256+4095*B^4<2*p`, and the
same selector and second-pass argument imply `0<=N(o)<p`. In particular
`x` is still Boolean and the native `(-x)&C` rewrite is valid without the
magnitude assumptions.

However first-pass wrap can lose input residue. For the concrete input
`[2^64-1,0,0,0,2^48]`, the first sum wraps from `2^64-1+C` to `C-1`.
The native output represents `C-1`, while the input's canonical residue
is `2^64+C-1`. Merely proving that an output is below the prime does not
establish input/output congruence.

## Solver and load-bearing controls

`prove.py` admits the full #115 digest, FDEs and body extents before proof.
It constructs the equations as unsigned 64-bit bit-vectors. Integer images
are zero-extended to 320 bits: any five-u64 representation is less than
`2^273`, and all signed identity differences have magnitude far below
`2^320`. Equality cannot silently hold by an integer difference of that
size, so this embedding has no hidden normalization modulus.

With pinned Z3 4.15.4 and a 30-second limit per query:

| Query | Actual expected/result |
| --- | --- |
| Any bounded violation of exact identity or range | UNSAT |
| Any unbounded output at least `p` | UNSAT |
| Any unbounded selector greater than one | UNSAT |
| Identity violation after removing input bounds | SAT, model replayed as ordinary integers |
| Threshold advanced by one, with input exactly `p` | SAT, mutated output remains `p` |

Unknown/timeouts fail the proof command; they are never reported as success.
The retained result binds the proof script SHA-256 and target digest.
The solver's off-domain witness is replayed by a separately evaluated Python
integer recurrence and checked for unequal residues. The threshold control
also replays the ordinary integer result. A finite set of 160 magnitude
corners and nine prime/carry boundaries supplements the quantified queries.

No claim covers memory faults, aliasing with saved stack state, all caller
preconditions, source history uniqueness, original ABI return typing,
microarchitectural timing, cryptographic operations or whole-node behavior.
The public function returns `void`; incidental RAX contents do not recover
a source return value. This packet adds static dependency evidence, not a
new Rust implementation or a full component acceptance gate.
