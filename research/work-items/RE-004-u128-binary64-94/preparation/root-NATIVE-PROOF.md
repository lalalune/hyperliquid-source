# Independent pre-Rust proof: unsigned u128 to binary64 bits

Target: node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Complete leaf: ELF VA `[0x565ff80,0x5660004)`, 132 bytes, 36 instructions,
body SHA-256 `bb4270c19daff730aafd37709cf9fa332cf7a809197157277af90ed0a7d88cdd`.
The parent independently read the complete retained GNU export before any
new unsigned132 Rust implementation. The author's native collector separately
binds the full ELF, executable mapping, FDE/CIE and unique relocation slot.
This proof does not claim the parent independently regenerated those mappings.

This is mathematical derivation from the complete static leaf. No captured
instructions, register-state interpreter or target executable were run.
The exposed relation is the returned XMM0 bit pattern for the unsigned integer
whose low word is RDI and high word is RSI. It is not a recovered Rust type,
private ABI, caller interpretation or full-component claim.

## Exact independent specification

For `n = 0`, return positive-zero bits. Otherwise let `e = floor(log2(n))`.
For `e <= 52`, let `q = n * 2^(52-e)`. For `e > 52`, put `s=e-52` and
`n=q*2^s+r`, with `0 <= r < 2^s`. Increment `q` exactly when
`r > 2^(s-1)` or when `r = 2^(s-1)` and `q` is odd. If the increment yields
`q=2^53`, replace `q` by `2^52` and increment `e`.
Return `((e+1023)<<52) | (q mod 2^52)`.
This is round-to-nearest, ties-to-even and produces finite positive normal
binary64 for every nonzero u128. Even the maximum u128 rounds to `2^128`,
whose biased exponent is 1151, below the infinity exponent.

The independently generated authority was frozen before Rust:
`FREEZE.json` SHA-256
`46fcb655e66a84595ac8786ab5c7a4ba67b4912ca7ce0a2329f51f34719b9230`.
It contains 16,614 rows / 16,610 distinct integers and was independently
corroborated for every row using CPython integer-to-float packing. Inputs and
expected output are separate, input-only-client protocol files. The generator
does not translate or execute captured instructions.

## Nonzero normalization and the zero BSR issue

Write `n=h*2^64+l`. For nonzero h the first BSR gives its highest set-bit rank;
XOR with 63 is `clz64(h)`. The second BSR may have an undefined destination if
l is zero, but TEST h and CMOVNE replace that candidate with the defined first
result. If h is zero and l nonzero, the second candidate is defined as
`clz64(l)+64`; the first undefined result is discarded. Thus, for every n>0,
the selected c is exactly `clz128(n)` in 0..127. This argument never treats
the destination of BSR(0) as a defined rank.

The variable SHLD/SHL operations use their count modulo 64. The conditional
selection on bit 6 of c chooses the correct high/low halves when c>=64.
Their resulting pair is exactly `N=n*2^c`, split as H=N>>64 and
L=N mod 2^64. At c=0 the count-zero instruction preserves its destination;
there is no assumed shift by 64. The highest set bit of N is bit 127.

## Retained prefix, guard and sticky information

The right shift of H by 11 produces `M=N>>75`, the retained 53-bit prefix,
with `2^52 <= M < 2^53`. The constant-count SHLD produces
`T=((H<<53) | (L>>11)) mod 2^64`. Its top bit g is N's bit 74, the guard bit.
The low-32-bit self move truncates L, then OR produces
`S=T | (L mod 2^32)`. S's top bit is still g. Its low 63 bits are zero if
and only if all N's lower 74 bits are zero. Duplicating some low bits in this
OR does not alter that zero/nonzero equivalence. Hence S preserves exactly
the needed guard and sticky predicate, with no unproved floating operation.

The NOT of M's low word and AND with g produce `t=g & (~M & 1)`.
The high bit of `(S-t) mod 2^64` is the rounding increment:

* g=0: t=0 and S<2^63, so the increment is zero.
* g=1 and M odd: t=0, so the increment is one.
* g=1, M even, no sticky bits: S=2^63 and t=1, so it is zero.
* g=1, M even, some sticky bit: S>=2^63+1; subtracting one retains the top
  bit, so the increment is one.

These are precisely less-than-half, above-half, odd-tie and even-tie rules.
When the integer fits 53 significant bits, normalization makes all discarded
bits zero, giving an exact conversion.

## Exponent assembly, carry and all-zero input

The exponent base is
`K=0x47d0000000000000-(c<<52)=(1023+126-c)*2^52`.
Adding M includes the implicit leading significand bit, thereby producing
biased exponent `1023+127-c`. Adding the rounding increment also implements
the significand carry into the exponent when M rounds from `2^53-1` to
`2^53`. This is the independent specification above with e=127-c.

For n=0 both BSR destinations may be architecturally undefined. The proof
quantifies over those possible values instead of assigning them zero. Both
data words are zero, so variable-count data shifts, the selected H/L, M, T,
S, g, t and the rounding increment remain zero for every masked shift count.
EAX is explicitly zeroed. The final OR of the original zero input words sets
ZF, and CMOVE selects that explicit zero instead of the potentially arbitrary
exponent base. Adding the two zero components returns exactly positive zero.
Intermediate flag values do not survive the final input OR used by CMOVE.

## Environment and closure limits

The complete body has no direct/indirect calls, RIP-relative data reads,
floating arithmetic or floating conversion. Its only XMM write is the final
integer MOVQ. Thus its returned bits do not depend on MXCSR rounding mode,
DAZ, FTZ or masked floating exceptions. Ordinary execution/return and readable
return-address premises remain; clobbers, other outputs, faults and callers
are not modeled as a new public API.

An independently authored integer implementation may use the specification;
it must not delegate to an integer-to-float cast or __floatuntidf and call
that reconstruction. A build-only cast control is suitable for testing an
object/IR guard, but must not be executed as a target surrogate. The original
machine-code correspondence from official compiler-builtins is separate from
new Rust behavioral evidence and must use actual artifact/relocation records.
