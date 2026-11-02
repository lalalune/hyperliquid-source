# Returned-bit contract

All addresses are ELF virtual addresses in the digest named by `static.json`.
The two complete FDE intervals contain no calls or external jumps. GNU binutils
2.47 and Apple LLVM 17 agree on every instruction boundary and retained byte.
The structural verifier checks both full body hashes, unique decoded FDEs,
their CIE records, internal branch destinations, one read-only -1 constant,
both RELATIVE slot destinations and absence of other overlapping relocations.
Incoming callers and the origin of their floating environment are not closed.

Let `b` be the input's low 64 bits, `s = b & 2^63`, and
`E = (b >> 52) & 2047`. The interpretation is conditioned on normal return and
intact code/data. Upper XMM bits, registers, flags and exception state are not
part of the new API.

## Truncation, 0x565f490..0x565f4e5

The unsigned comparison at `0x565f4a2` returns the input when `E > 1074`.
This includes all large finite integers, infinities, and every signaling or
quiet NaN bit pattern, without floating arithmetic or comparison.

Otherwise the arithmetic right shift at `0x565f4ba` forms a candidate mask.
For `E < 1023`, the conditional move at `0x565f4cd` discards that candidate
and selects just the sign mask. For `1023 <= E <= 1074`, its count is
`E - 1023`, between 0 and 51, so the selected mask is
`~(2^(1075-E)-1)`. The low 52 or fewer fractional bits are cleared. Testing
them first only avoids an unnecessary move; the low result is identical.
Thus truncation preserves sign, including negative zero, and clears only the
fractional portion. No MXCSR field can affect these bit operations.

## Floor, 0x565f6f0..0x565f784

The first unsigned branch likewise returns unchanged bits when `E > 1074`.
For `1023 <= E <= 1074`, let `u=2^(1075-E)`, `m=u-1`, and `q=b & ~m`.
The body computes `b & m`, and leaves an integral input unchanged. Otherwise
the sign-replicating shift, mask, add and clear at `0x565f731..0x565f74e`
give `q` for a positive input and `q+u` for a negative input. This is floor.
The largest negative result is `0xc330000000000000` (magnitude 2^52), so the
Rust addition cannot overflow u64. Every Rust shift count is between 1 and 52.

For `E < 1023`, nonnegative bits return positive zero. Negative bits take
`CMPSD` equality against positive zero at `0x565f766`. A true result masks
the **original input bits** into the return value; a false result selects the
constant `0xbff0000000000000` at `0x20a278`. Hence negative zero stays negative
zero, and ordinary negative fractions return -1.

The [Intel architecture manual](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366521.pdf),
Vol. 1 sections 10.2.3.4 and 11.5.2.2, specifies that DAZ makes denormal
operands behave as signed zero during floating computation and suppresses the
denormal exception. Therefore with DAZ set a negative subnormal compares equal
to zero, and the subsequent bitwise AND/OR returns its original subnormal
bits. With DAZ clear it compares unequal and returns -1 if the denormal
exception is masked. With that exception unmasked, normal return is outside
the contract. FTZ and rounding mode do not change this comparison-only path.

This conclusion is an architectural inference from the captured instructions;
no original instruction was executed or emulated to measure the two modes.

## Independent finite corpus

`verify_static.py` decodes finite inputs into exact integer numerator and
power-of-two denominator, performs mathematical quotient/remainder rounding,
and encodes the exact integral result. It handles exceptional bit patterns by
the proven early-return rule and adds only the comparison-specific DAZ case.
This formulation differs from the Rust bit masks and increment.

The 66,132 rows cover every exponent field, both signs, both DAZ states,
integer boundaries, subnormals, zeros, NaNs and 4,096 deterministic mixed bit
patterns. Their hashes were generated before writing the Rust source.
The proof covers the full bit domain under the stated return conditions;
the finite native runs are regression evidence, not exhaustive execution.
