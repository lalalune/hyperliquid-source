# Exact numerical output words

This proof supplies the numeric relation for [PROOF.md](PROOF.md). It is conditional on documented Intel SSE2 behavior, RN-even, DAZ=0, FTZ=0, masked floating-point exceptions and preservation of those controls by required ordinary callbacks. Those runtime controls were not measured. Exception flags, traps, timing and diagnostic floating-point activity are excluded.

The exact numeric helper is 0x3423120..0x34233b4,660 bytes / 186 retained rows, body SHA256 `378598f507c8bf24f338bfdb337d4dbc40c5feeb4f0fa0824ed8a07fc04cf83a`. [obligations.json](obligations.json) binds its full body, constants and encoded operands.

## Unsigned and signed integers

For u64 n=H·2^32+L,0≤H,L<2^32, PUNPCKLDQ at 0x3423364 constructs exactly 2^52+L and2^84+H·2^32 using data 0x451210. SUBPD at 0x3423370 subtracts the exact biases [2^52,2^84] from 0x450170. Both differences, L and H·2^32, are exactly representable. The ADDSD at 0x3423380 is therefore the only potentially rounded operation: its result is RN-even(n).

For n>0 with bit length k≤53 the result is exact. Otherwise s=k−53 lies in 1..11; writing n=q·2^s+r, increment q exactly when r>2^(s−1), or on equality when q is odd. A carry advances the binade. This scalar mathematical rule covers all u64 values: u64::MAX rounds to 2^64, not saturation. Neither bias subtraction nor the final finite result underflows or overflows.

Signed i64 uses0x342333b and the signed RN-even relation; −2^63 is exact. Accepted narrower integers are exact. Intel specifies nearest-even and the SIMD rounding control in Table4-8/§4.8.4. [Intel Vol1,253665-080US,June2023](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf).

## Every binary32 pattern

Let S be sign,E the 8-bit exponent,F the 23-bit fraction. The output bit word is:

| Input | Output bits |
|---|---|
|E=0,F=0|S·2^63|
|1≤E≤254|S·2^63 OR (E+896)·2^52 OR F·2^29|
|E=0,F>0|S·2^63 OR (k+874)·2^52 OR (F−2^k)·2^(52−k), k=floor(log2F)|
|E=255,F=0|S·2^63 OR 0x7ff0000000000000|
|E=255,F>0|S·2^63 OR 0x7ff0000000000000 OR F·2^29 OR 2^51|

Normal finite widening only appends fraction zeros. For subnormal F, its value F·2^-149 normalizes with k∈[0,22] to exponent k−149. Even the smallest nonzero result2^-149 is normal binary64. Finite widening is exact, with no output underflow/overflow or rounding dependence. DAZ=0 matters for subnormal input; FTZ cannot change these normal widened outputs.

For NaNs, Intel TableD-11 explicitly supplies shifted payloads and quieting, including signaling inputs. The resulting bit 51 is set; the original payload is otherwise shifted 29 places. The table is a generic ISA premise, not a measured native result. [Intel Vol1,TableD-11,printedD-8](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf).

After CVTSS2SD at 0x342316c, the native code independently restores the original sign: NOT(raw32)>>31 selects [−1,+1] at 0x456510;0x4559c0 extracts its sign;0x450180 strips the converted sign; OR combines them. This also preserves negative zero and negative NaN sign.

## Raw binary64, flags and portable source

The cb route at 0x342328a..0x34232b2 uses integer load/byte swap/store. It preserves every 64-bit word, including signaling NaNs and subnormals, without applying the f32 quieting rule. The binary visitor's four u8 values 0..255 convert exactly.

Masked exceptions permit the chosen output relation, but native sticky flags can change for signaling NaNs, subnormal inputs or inexact integer conversions. An unmasked exception can prevent ordinary completion. DAZ/FTZ behavior and masks are described in Intel §10.2.3; no flag or trap equivalence is claimed. [Intel Vol1](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf).

A generic Rust floating cast is insufficient to guarantee these exact NaN words: Rust1.95 permits multiple arithmetic/cast NaN payload/sign outcomes, while raw bit operations preserve stronger identities. The source can implement the chosen output words with integer operations without inheriting host FP controls. [Rust1.95.0 NaN documentation](https://github.com/rust-lang/rust/blob/1.95.0/library/core/src/primitive_docs.rs#L1230-L1293).

The 62 [scalar JSON witnesses](scalar-pre-source.json) were frozen before source: 24 u64, 28 binary32, 6 raw binary64 and 4 i64 boundaries. An independent exact-rational check compared manual finite values and adjacent representable integer answers, without host float conversion or captured evaluation. This is finite corroboration of boundary arithmetic, not an enumeration of all bit patterns. The [scalar TSV](scalar-cases.tsv) embeds those unchanged expected words in array inputs after source authorship; [VALIDATION.md](VALIDATION.md) records that projection and actual test results.
