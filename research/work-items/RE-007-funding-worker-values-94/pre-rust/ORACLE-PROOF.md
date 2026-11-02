# Independent rational oracle

`oracle.py` does not load the target or parse disassembly, and has no instruction
state, program counter, host floating-point arithmetic or compiled source
dependency. It evaluates the mathematical successful-domain contract in
CONTRACT. This is not captured execution or an instruction evaluator.

A finite binary64 word denotes sign*(fraction+implicit_bit)*2^power, where
subnormal exponent0 has no implicit bit and power=-1074. The Fraction decoder
therefore gives its exact real value, including subnormals. Among nonnegative
finite encodings 0..0x7fefffffffffffff the represented values strictly increase.
Binary search finds the largest encoding with value <= the exact input; the
next encoding is the adjacent upper value. Exact rational distances choose the
nearest. At a tie, the encoding with even low bit is the even significand,
including exponent transitions and zero/subnormal or subnormal/normal seams.
For negative inputs symmetry gives the same RN-even magnitude and negative
sign. Exact zero's sign is handled separately, without Fraction inventing one.

The overflow midpoint is 2^1024-2^970, halfway between maximum finite and the
next exponent's exact 2^1024. RN-even reaches infinity at or above that midpoint;
below it the adjacent finite calculation chooses maximum finite when needed.
At underflow, the adjacent-zero rule naturally selects zero for half the least
subnormal and the even subnormal for higher halfway values. No host conversion
or rounding algorithm from the planned u128 implementation is reused.

Integer conversion calls this search on the exact signed integer. Multiplication
then calls it again on the product of that rounded integer's exact Fraction and
the exact finite rate. A nonfinite rate is sufficient for amount0 regardless
of whether the original multiplication's class is NaN or infinity (including
zero times infinity); that distinction is deliberately not an API output.
A finite multiplication which rounds to infinity also gives amount0. Otherwise
the native clamp/truncate theorem supplies the exact i64 amount and MIN refusal.
Raw rate bits are carried independently and never replaced by these classifications.

The worker oracle first classifies positions and filters eligible emitted rows,
stopping on the first guarded refusal. It derives each position's local fields
separately, with an ordered fold only for the shared balance, and computes the
first maximum by an argmax over `(absolute_product,-row_index)`. Summary is an
ordered saturating fold; it is not an arbitrary-precision total clamped once.
Diagnostics are appended in per-position field order and then summary order.
This separates value derivation from the planned production's direct ordered
state transitions. It cannot independently establish the native proof premises.

Thirteen exact mathematical controls cover signed zero, normal-integer ties,
subnormal ties, overflow midpoint and predecessor, finite MIN versus infinity,
positive saturation after integer rounding, and reciprocal modulus bounds.
The fixture classes add raw signed/signaling/quiet NaNs, infinities, both zeros,
exponent seams, integers around 2^53 and i64 limits, every modeled accumulator
saturation, unrelated raw tags, missing rates, membership and raw time gates,
out-of-range metadata and checked product precedence, first-max ties and ordered
sum saturation, plus deterministic composed states. Finite examples supplement
the universal proof; they are not exhaustive all-bit native qualification.
