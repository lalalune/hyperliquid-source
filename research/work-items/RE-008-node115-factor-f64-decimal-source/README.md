# Factor parser's binary64-to-decimal fallback source

Target `node/115`: SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. The target was inspected statically and was not executed or emulated.

## Scope and credited prior work

`l1-shared-f64-to-decimal-115` already specifies `0x5c43c60`, its flag modes, `0x43099f0`'s caller path, and retained arithmetic observations. This contribution implements the actual caller-selected mode in Rust and validates it against those retained observations, plus independent arithmetic and bit-pattern checks. The algorithm is credited to that evidence packet, not presented as a new discovery.

This is the opposite conversion from PR #7058's decimal96-to-binary64 source. It does not duplicate that source, nor implement the decimal string parser or general floating-point text grammar. It supplies the bounded numeric dependency needed by the factor fallback after successful float parsing.

## Actual caller and numerical contract

At `0x43099f0`, the first parser is bound by relocation `0x64e95c0 -> 0x5c44210`. Its raw tag 6 bypasses the fallback and returns decimal success `0x1a2`. Otherwise the float parser is `0x64e0048 -> 0x16876b0`. Float parse failure, a nonfinite value, or conversion refusal becomes raw `0xb0`.

For a finite nonzero binary64 value, the caller extracts its sign, fraction and exponent. A normal value adds the implicit bit 52 and uses exponent `biased_exponent - 1075`. A subnormal uses the raw fraction and exponent -1074. It calls `0x5c43c60` with both `is64` and rounding flags equal to one. Signed zeros bypass the kernel and retain the sign bit with zero coefficient and scale zero. This crate reconstructs that successful-float-parser numeric branch through `from_f64_bits`.

The kernel works with a 96-bit coefficient and a signed decimal exponent:

- For positive binary exponent, it shifts left while the coefficient's high bit permits. When bit 95 is set, it divides by five instead, leaving an extra decimal power to restore later. Integer division truncates.
- For negative binary exponent, it shifts an even coefficient right, adjusting the decimal exponent. An odd coefficient is multiplied by five when that fits 96 bits; otherwise it is shifted right. This can discard binary information.
- Any positive remaining decimal exponent is discharged by multiplication by ten; 96-bit overflow refuses conversion.
- A scale above 28 is reduced by repeated division by ten with half-up rounding at each step. When the division's quotient would be zero, the native early exit produces scale-zero zero before rounding. It does not revive the remainder into one unit.
- With the caller's `is64=true, round=true` flags, further decimal division/half-up rounding reduces a coefficient at or above 2^52 while the scale remains positive. Finally, removable trailing decimal zeros are stripped.
- The sign is applied to the decimal flags. It is retained even if the coefficient underflows to zero.

This is not shortest-decimal formatting or one-shot exact rational rounding. At the upper edge, exactly binary64 2^96 follows the divide-by-five path and produces coefficient `2^96 - 6` at scale zero; the next larger binary64 value refuses. A blanket mathematical `abs(value) > decimal::MAX` check would change this native behavior.

`Decimal96::words` returns native storage order: flags, high32, low32, middle32. Successful values have a 96-bit coefficient and scale 0..28. The public `from_binary_parts` kernel accepts coefficients within 96 bits and exponents -1074..1023, with the caller's two flags fixed to one. Those explicit bounds are host-interface guards. Other flag combinations and out-of-domain raw kernel exponents are not reconstructed by this source. Constructing arbitrary public `Decimal96` fields does not validate a native value.

## Evidence and validation

`records.json` retains both complete FDEs: 528 instructions, 134 instruction witnesses, two parser relocations and the 12-byte zero coefficient constant. `verify.py` checks target identity, exact bytes, instruction transcription, FDEs, selected facts and bindings; 15 negative controls reject wrong parser/gate/sign/exponent/precision/rounding interpretations. These checks do not execute the target.

Terra extracted the existing packet's retained observations into frozen tests: nine unique caller bit patterns and 415 `is64=1, round=1` kernel tuples inside this API's exponent domain (340 successful raw-word outputs and 75 refusals). One retained tuple with exponent 1088 is intentionally outside the interface. The prior packet mentions a larger aggregate corpus; its absent individual records are neither regenerated nor claimed as executed here. The new source agrees with every retained in-domain tuple.

Independent source tests use the exact integer formula for positive and negative powers of two in a range where the conversion is exact, check sign symmetry and output-domain invariants over 4,096 deterministic bit patterns, distinguish signed zeros/nonfinite inputs, and test the 2^96 boundary. Debug/release tests, formatting, strict Clippy and repository catalogue/reproduction/static checks are recorded during packaging. No live service, target process or target emulator is used.
