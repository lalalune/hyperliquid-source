# Integer source correspondence for every raw input

This argument concerns the separately frozen `src/visor-duration-value/src/lib.rs`,
not the original compiler or ABI. The earlier immutable pre-code proof, ISA
premises, native bytes and Fraction corpus remain unchanged. No production build
is claimed by this source proof.

Let b be any u64 and e=(b>>52)&2047. The first source guard returns zero for every
negative encoding, every exponent2047 encoding, and e<992. The native theorem
already proves zero for negative/nonfinite/zero inputs and the entire tiny
interval. In particular, both zeros and all subnormals are covered; no implicit
normal significand is formed for a subnormal. Positive finite e>=1087 is exactly
the remaining x>=2^64 class.

For that large class, unsigned positive binary64 encodings are monotone by exact
value. The frozen midpoint certificate proves the first million-fold overflow
encoding is `7eb0c6f7a0b5ed8d`. The source compares against this exact constant,
without multiplication in a host floating format. Below it, integer division of
u64::MAX by1,000,000 gives seconds18446744073709 and remainder551615. Multiplying
the latter by1000 gives nanoseconds551615000. At or above the threshold, the
source returns zero. This is the admitted native fallback relation, including
the discontinuities at2^64 and at the overflow boundary.

All remaining inputs are positive normal e in992..1086. The source forms
M=2^52+(b mod2^52), so2^52<=M<2^53. Let P=M*10^9. Since10^9<2^30, P<2^83 and the
u128 multiplication is exact. The exact real total nanoseconds is
P*2^(e-1075), with no prior binary64 rounding.

For e>=1075, shift e-1075 lies in0..11. The left shift yields the exact integral
total, below2^94 and hence below u128 capacity. For e<1075, shift s=1075-e lies
in1..83. `1_u128 << s` and `1_u128 << (s-1)` are valid. The right shift and mask
give q=floor(P/2^s) and r=P mod2^s. The increment predicate is precisely r>2^(s-1),
or equality with odd q. Therefore q+increment is nearest-even rounding of the
exact total. The increment cannot overflow: q+1<=P+1<2^84.

Dividing this one rounded total by10^9 handles the fractional carry automatically.
The remainder is in0..999999999 and fits u32. The seconds cast also loses no bits:
for e<=1074, x<2^52 and the rounded result's seconds is at most2^52; for e>=1075,
x is already an integer and the maximum ordinary input is2^64-2048. Thus every
seconds result is below2^64. No unchecked memory, variable-size allocation,
floating instruction, environment or external call is needed by the library.

The private fields can only be produced by these branches; accessors preserve
them. The new host type is canonical without claiming a native struct layout.
The source uses one significand product and one rounding boundary for all
ordinary exponents, rather than the native subsecond/fractional register regimes
or the pre-code oracle's Fraction distances. Independent authoring does not
create a second target lineage or make finite corpus matches a universal machine
equivalence theorem; the conditional native proof supplies that bridge.
