# Equivalence of the Rust scalar rule to the closed node94 leaf

The predecessor's [static proof](../RE-001-ceil-f64-94/PROOF.md) establishes
the low-word result of the complete 119-byte FDE for all input encodings,
assuming intact mapped code/constants and ordinary return. Its full-target,
FDE, data and caller-slot bindings are rechecked before each Rust comparison.
This argument relates that established result to the newly authored Rust
source. It is not a formal verification of the Rust compiler.

Let `b` be an arbitrary u64 word, `E = (b >> 52) & 0x7ff`, and `s` its sign.

For `E >= 1075`, both definitions return `b` unchanged. This includes every
infinity and NaN encoding; neither quieting nor payload canonicalization is
performed. For `E < 1023`, both return positive zero only for `b = 0`, negative
zero for every negative encoding in this exponent range, and +1 otherwise.
In particular, negative zero survives the sign branch.

For the remaining `1023 <= E <= 1074`, define `k = 1075 - E`, `u = 2^k`,
`f = b & (u-1)`, and `q = b & ~(u-1)`. Thus `b = q + f` and `0 <= f < u`.
The Rust expression returns `q+u` exactly when `s=0` and `f!=0`, otherwise `q`.

The target-derived equation for this interval is
`(b + (s=0 ? u-1 : 0)) & ~(u-1)`. For negative inputs it gives `q`. For
positive inputs with `f=0`, adding `u-1` does not carry into `q`, so it also
gives `q`. With `f>0`, `u <= f+u-1 < 2u`; clearing those low bits therefore
gives exactly `q+u`. These cover every possible input in the interval.

All Rust integer operations are defined on this domain. The shift count `k`
is between 1 and 52. Subtracting one from `u` cannot underflow. Only positive
finite encodings reach `q+u`; its largest possible result is the encoding
`0x4330000000000000` (+2^52), below u64 overflow. The negative branch clears
bits without adding. The build additionally enables overflow checks at both
optimization levels.

The three intervals partition all 2^64 input words. The source-level scalar
result therefore agrees with the predecessor's qualified target contract.
The typed wrapper only converts `f64` to/from its bit representation and
delegates to this rule. It introduces no floating-point arithmetic or a new
rounding policy.

The native checks exercise both public APIs on the predecessor's frozen
33,066-case corpus and exact rational expectations. Their input/expected
hashes must match the predecessor's published record before compilation.
These executions test newly built Rust, not the captured binary. They
corroborate the source argument and observed host build; they are not an
exhaustive execution over 2^64 inputs or original-byte equivalence.
