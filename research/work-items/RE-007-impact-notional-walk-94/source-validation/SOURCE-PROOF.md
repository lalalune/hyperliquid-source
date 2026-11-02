# Authored integer implementation correspondence

This source phase follows immutable pre-code freeze
`b1c53a69adb1b9d85af70e397cf2b6828f7f11009ce2256563fa45411b3ae9b2` and the
coordinator's source-authoring gate. The original published20 and pre-code32
files are unchanged. This proof concerns the new dependency-free component
`src/node94-funding-premium-values`, not native source types/compiler/ABI or a
generic floating-point package. No compilation is claimed by this document.

## Logical data and complete walk

`Book` has two borrowed entry slices and one common slot slice. Both calls to
`impact` use that same slice/count; no hidden per-side bound remains. Entry
key/active/head and slot tag/quantity/continuation/next have precisely the
frozen logical widths. Rust layout and names are new. The immutable slices
may share slots between entries or trees, and are never mutated or sorted.
Source has no allocation/callback/hash/metadata/scheduler behavior.

For any logical input with positive target, the sequential `cost,quantity`
state implements the pre-code prefix theorem. Bit0 and initial index checks
precede the reached chain; an invalid initial index returns0. The chain checks
dword tag2 before quantity, saturates the quantity sum, tests the complete
continuation word, and treats invalid later index as the accumulated chain's
end. `usize::try_from` followed by comparison cannot admit an out-of-range u64
on any host: a failed conversion is necessarily outside a representable slice.

The per-chain budget begins at the common `slots.len()`. Every slot read spends
one unit. A finite chain that terminates without repeating an index reads at
most that many distinct slots and cannot refuse. In stable immutable slots,
revisiting a previously read nonterminal slot enters a permanent cycle: its
tag/continuation/next do not change, so termination cannot appear on a later
visit. Conversely, more than N valid reads among N slots implies repetition.
Budget refusal therefore has the same new safe-policy class as the oracle's
visited-set test. They need not refuse after the same number of repeated reads;
there are no callbacks/effects in this value API. Budget resets for every entry,
allowing slot reuse across entries/trees. Unvisited slots, ignored next fields,
tag2 suffixes and entries after early return do not cause refusals.

`unsigned_abs` gives the magnitude of every i64, including MIN ->2^63. With
q<=2^64-1, the full u128 product is less than2^127. The source tests the complete
product against2^63-2 before any crossing/partial calculation. Therefore its
cast to u64 loses no bits. Continuing requires candidate<target; a saturated
candidate is U64_MAX and cannot satisfy this since target<=U64_MAX. Thus every
continued cost is the exact prefix sum and remains strictly below target.
Quantity uses u64 saturating addition exactly as the native value relation.

At a crossing, positive target and cost<target imply price>0 and
`partial=floor((target-cost)/price)<=level_quantity`. Consequently price*partial
fits below the already checked full product cap, and cost+that product<=target
fits u64. Neither ordinary multiplication/addition nor the subtraction/division
can overflow, underflow or divide by0. Saturated final quantity and the explicit
`quantity==0 || quantity>cost` guard are equivalent to the native wrapped
`(quantity-1)>=cost` test. Accepted division is unsigned floor. Exhaustion,
zero quantity, inactive entries and invalid initial indices return0 as frozen.
The oracle independently uses unbounded prefix sums and first-crossing selection;
it does not import this running-state implementation.

## API ordering, policy and selected output

`evaluate` rejects scale>6 before oracle zero, as required by the addressed
native metadata/scale corridor. It then returns absence for raw oracle0 before
target/books. Replacing the native zero conversion/division with a raw-zero
test preserves the value because D>0 and RN(0)/D is+0; exception flags/timing
are outside the API. Nonzero oracle with target0 is a new refusal before walking,
not a claimed uniform native target0 result. Both ordinary impacts are computed
before either is tested for0; the code propagates reached-cycle policy separately.
The ordinary second-call ordering remains a source-review invariant, not an
output-only coverage claim. Its policy-only CycleSecond witness is labelled.

Absence carries no inactive premium fields and produces exactly asset/tag1/raw
oracle. Success produces all three active fields and asset/tag0/premium bits.
None of the supplied metadata/hash/set boundary values is recomputed. Complete
native correspondence still uses the frozen valid-tree, stable-view, selected
lookup, normal helper, exact copy/allocation/frame and floating-environment
premises. The host operation does not itself require a floating environment.

## Integer binary64 representation and rounding

For each nonzero normal finite input word to a private arithmetic helper,
`parts` returns a53-bit unsigned significand m and signed power p such that
the exact magnitude is m*2^p. Here2^52<=m<2^53 and
p=stored_exponent-1075. A sign bit is handled separately. These helpers are
private and only called through the finite domain established below; they
do not accept arbitrary public raw floating encodings.

`round_scaled(sign,n,p)` rounds the exact nonnegative integer n times2^p.
Zero produces+0, appropriate for exact nearest-even cancellation and unsigned
zero conversion. For n!=0 let w=bit_length(n),1<=w<=128. When w<=53, shifting
left53-w gives an exact normalized significand, and subtracting that shift from
p preserves the value. Otherwise k=w-53 lies in1..75. The code obtains the
lower significand q=floor(n/2^k), remainder r=n mod2^k and midpoint2^(k-1).
It adds one precisely when r exceeds the midpoint or equals it with odd q.
This is nearest-even rounding to the two adjacent representable significands.
Every shift/mask is within u128. q+1<=2^53, so the increment cannot overflow.

`encode` handles the sole rounding carry q=2^53 by replacing it with2^52 and
incrementing p. Otherwise the significand is already in[2^52,2^53). Encoding
stored exponent p+1075 and the low52 bits is exact. The reachable-domain proof
below ensures that this exponent lies in1..2046; no truncating cast implements
subnormal, overflow, NaN or out-of-domain behavior. Unsigned conversion is
`round_scaled(0,u128::from(u),0)` for every u64. In particular U64_MAX rounds
to2^64 without a signed cast or wrap. This is the single RN(u) operation proved
for both native SIMD constructions, not a reused integer-to-float mnemonic.

## Exact finite addition/subtraction without an instruction evaluator

`finite_add` handles signed zeros first: two zeros retain a negative sign only
when both are negative, while a lone zero leaves the other finite operand.
For nonzero magnitudes, raw positive-normal encodings are monotone, so comparing
their signless words selects the larger magnitude L. Write normalized powers
pL>=pS and d=pL-pS. If d<=75, the code represents both exactly at power pS:
`N=mL*2^d +/- mS`, choosing addition for equal signs and subtraction otherwise.
Magnitude selection ensures subtraction is nonnegative. The maximum sum fits:

```
(2^53-1)*(2^75+1) = 2^128 - 2^75 + 2^53 - 1 < 2^128.
```

Hence neither shift nor sum overflows u128 for any d in0..75. One call to
`round_scaled` rounds this exact result once, with the larger operand's sign.
Exact opposite-sign cancellation has N=0 and returns+0 under nearest-even.

If d>75, the smaller value in units of the larger significand's least bit is
`mS*2^-d <2^53*2^-76 =2^-23`. Away from a binade boundary, a rounding midpoint
is half such a unit away; even beside an exact power of two the smaller adjacent
spacing is half a unit, so the closest midpoint is a quarter unit away. Since
2^-23<1/4, adding or subtracting the smaller operand must round strictly back to
the exact larger operand, with no tie. This covers both signs. It does not use
an inexact sticky-bit subtraction or treat every exponent gap as zero.

`finite_sub(a,b)` flips b's sign and uses this same exact-add proof. It retains
the observed operation order: gap mode computes b-oracle before XOR, separately
computes a-oracle, then applies source-operand MAX with+0. Any intermediate-0
from XOR is discarded by that MAX as in the native finite-equality rule.

## Division by a positive finite binary64 denominator

This is a fresh denominator proof. The earlier funding-rate denominator was a
positive rounded integer count; the scaled oracle here is generally fractional,
so that restricted proof is insufficient and is not imported.

For nonzero numerator magnitude a=ma*2^pa and positive normal denominator
b=mb*2^pb, both ma and mb lie in[2^52,2^53). Their ratio is strictly between
1/2 and2. If ma<mb, choose k=53; otherwise k=52. Then the exact scaled ratio
`ma*2^k/mb` lies in[2^52,2^53), so its floor q is a53-bit significand. The
integer numerator ma<<k is below2^106 and fits u128. Division/remainder by mb
are exact and nonzero-denominator. Twice the remainder is below2^54.

The code increments q when2r>mb or when2r==mb and q is odd. These are exactly
the adjacent-significand nearest-even distance and tie tests. The rounded q is
at most2^53; `encode` handles that carry at power pa-pb-k. The numerator's sign
is retained because the denominator is positive. A zero numerator returns its
sign unchanged. This covers every53-bit positive denominator significand,
including the scaled non-integer oracle, all D values and100, with no host FP,
unbounded production arithmetic or constant expected-output table.

## Reachable exponent domain, comparisons and exact half

The frozen native proof applies identically to the source helper relations:
scale0..6 makes D=10^(6-scale) an exact integer1..10^6. Raw oracle>0 converts to
a positive normal RN(u)<=2^64; division by D produces o>2^-20 and o<=2^64.
On an active path both impacts are positive, so their scaled a,b have the same
bounds. The exact midpoint inequality in the pre-code proof excludes a zero
rounded oracle. Therefore every divisor is positive normal.

The following conservative nonzero-result bounds stay far inside the normal
binary64 exponent interval[-1022,1023]:

| Operation family | Bounds sufficient for source packing |
| --- | --- |
| unsigned conversion | 1..2^64 |
| scaled oracle/impacts | strictly greater than2^-20, at most2^64 |
| scaled-price differences and difference of selected gaps | at least2^-72 in magnitude, at most2^65 |
| gap/oracle and optional/100 | above2^-145 in magnitude, below2^87 |
| sum and midpoint | positive, above2^-20, at most2^65 |
| midpoint/oracle, then subtraction of1 and optional/100 | positive ratio before subtraction; final nonzero magnitude above2^-145 and below2^87 |

Scaled inputs are integer multiples of2^-72; a nonzero difference cannot be
smaller than that quantum. Quotient/division rounding leaves the conservative
lower margin above2^-145. In the midpoint branch the ratio's subtraction from1
is either exact+0 or at least the predecessor spacing2^-53 near1, and larger
away from1. These are universal input-domain bounds, not sampled extrema.
They justify every private helper's normal-or-zero premise and the exponent
cast in `encode`. Infinity/NaN/subnormal support is not silently invented.

For midpoint, `finite_add(a,b)` is positive normal and<=2^65; its raw exponent
is well above1. Subtracting1<<52 from the positive encoded word decreases only
that exponent by one and gives exact multiplication by0.5. No borrow reaches
the fraction/sign and no subnormal can arise. The native half-each fallback is
unreachable on these bounded operands. Division followed by `finite_sub(...,ONE)`
is exactly the observed division followed by addition of-1 in this finite domain.

`less` compares both zeros equal, orders opposite signs, and reverses encoded
order for two negatives. It therefore implements exact finite ordering.
`source_max` and `source_min` choose the second operand on equality, including
signed zero. They implement gap selection and the native ordered finite clamp.
The optional division by100 precedes clamp. Every public active result is
finite, lies in[-0.5,0.5], and has+0 for any zero, as the frozen theorem states.

## Qualification boundary

The6034 pre-source expectations remain immutable and independent: Fraction
bisection/adjacent-distance rounding plus unbounded prefix sums preceded this
u128/significand implementation. The input-only client must call this actual
crate and receive only raw inputs. Later exact source/graph/toolchain freeze,
coordinator build gate and real debug/release qualification are separate steps.
Mathematical witnesses, static review and this proof do not claim an observed
build, compiled-mutant kill or universal captured-machine equivalence.
