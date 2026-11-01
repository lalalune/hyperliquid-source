# Full signed-i128 returned-bit relation

The complete 168-byte node94 leaf at ELF VA `[0x565f4f0,0x565f598)` takes
raw low/high words from RDI/RSI. Interpreting those words as a two's-complement
signed integer `v` is an inference from the observed sign/magnitude operations.
This proof covers the low 64 output bits moved into XMM0. It does not establish
a source name, original ABI integration or compiler provenance.

The leaf uses only integer arithmetic and a final MOVQ. It contains no call,
branch, explicit data-memory operand or floating arithmetic. Its numeric output
therefore does not depend on MXCSR rounding controls. Valid code and normal
return-stack premises are assumed; trap delivery and register/flag preservation
are outside the value API.

Architecture premises follow Intel's September 2016 instruction reference:
[Volume 2A, BSR, p. 3-110](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
for zero-operand destination uncertainty, and
[Volume 2B, SHLD, pp. 4-611–4-612](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
for operand combination and the six-bit count mask in 64-bit operation.
The following derivation is specific to the retained node94 instructions.

## Sign and magnitude, including the minimum signed integer

At `0x565f4f0..0x565f516`, the sign is the high input word's bit 63. Arithmetic
right shift by 63 produces either zero or the all-ones word. XOR of both words
with that mask, followed by SUB/SBB of the same mask, computes the unsigned
magnitude `m=abs(v)` modulo `2^128`. For negative inputs this is the two-word
operation `~raw+1`, with the low-word carry propagated into the high word.
For every signed i128 input, `0 <= m <= 2^127`; in particular the minimum input
has magnitude `2^127`, which fits unsigned 128 bits. No signed negation overflow
is imported into Rust: `unsigned_abs()` expresses exactly this domain.

## Normalize every nonzero magnitude

The two BSR operations and XOR-with-63 produce the number of leading zeros in
each nonzero word. The low-word count has 64 added. The high-word nonzero test
selects its count when present. Therefore for `m != 0`, RCX is
`l = 127-floor(log2(m))`, in `0..127`.

A BSR destination is architecturally undefined for a zero operand. This proof
does not assume an unchanged destination or a particular CPU's result:

- If the high word is zero and the low word nonzero, the high-word BSR result is
  discarded by the later conditional move.
- If the high word is nonzero, the low-word BSR result is discarded by that move.
- If both words are zero, the separate zero proof below does not need either
  destination to have a particular value.

SHLD and SHL use `l mod 64`. The subsequent test of `l`'s bit 6 moves the shifted
low word into the high word and clears the low word when `l >= 64`. Together
these operations yield the complete unsigned 128-bit value `m << l`, written as
high word `H` and low word `L`. Every selected hardware shift is within its
64-bit operand width; no oversized-count SHLD semantics are required.
For nonzero input, H's top bit is one.

## Guard, sticky information and nearest-even rounding

The retained significand is `J = H >> 11`, containing 53 bits. The complete
75-bit discarded suffix is

```text
R = ((H mod 2^11) * 2^64) + L.
```

The SHLD by 53 and the later OR compute

```text
T = ((H << 53) mod 2^64) OR (L >> 11) OR (L mod 2^32).
g = (T >> 63) = ((H >> 10) AND 1).
```

The first two terms are the actual SHLD result. The final low-dword term is
included because MOV R8D,R8D zero-extends L's low 32 bits before OR. This is
not a lossless encoding of R, nor does the proof treat it as one. It preserves
exactly the predicates the rounder needs:

- `g` is R's top bit, the halfway/guard bit.
- T's lower 63 bits are zero exactly when R's lower 74 bits are zero: H's
  lower ten bits survive at T bits 53..62; L bits 11..63 survive in `L >> 11`;
  L bits 0..31 survive in the final OR. These covered sets include all L bits.

The target computes the increment

```text
increment = (T - (g AND NOT(J AND 1))) >> 63.
```

Here the subtract is u64. If g is zero, the subtrahend is zero and the result's
top bit remains zero. If g is one and J is odd, the subtrahend is zero and the
increment is one. If g is one and J is even, subtracting one clears T's top
bit exactly when `T=2^63`; otherwise it remains one. This branch cannot
underflow because `T>=2^63`.

Thus the increment is one for a suffix greater than halfway, and for an exact
halfway only when the retained significand is odd. This is nearest-even
rounding of the positive magnitude. Adding the original sign produces the
same nearest-even rule for negative inputs; there is no directed rounding.

## Exponent construction and carry

The integer constant `0x47d0000000000000` equals `(1022+127) << 52`. Subtracting
`l << 52` gives `(1022+e) << 52`, where `e=floor(log2(m))`. The target ORs the
sign into J, adds this exponent base, then adds the increment. Because J
includes its implicit bit 52, this yields the binary64 biased exponent
`1023+e`. A rounded J equal to `2^53` carries naturally into the next exponent.

For signed i128, `e<=127`. Positive values approaching `2^127` may round to
that value; the negative minimum is already exact. Every result is finite and
normal except zero. The magnitude result stays strictly below the sign bit,
so preserving sign by OR before the additions is equivalent to OR afterwards.
There is no u64 addition overflow on this domain.

For `e<=52`, all bits of m fit the significand and the discarded suffix is
zero. For `e>52`, Rust retains `m >> (e-52)` and compares the remaining bits
to `2^(e-53)`. Its shift is in `1..75`, so all u128 shifts/masks are defined.
That comparison is the same greater-than-halfway/tie-parity relation derived
above, expressed directly without the target's compressed sticky word.

## Zero is defined despite undefined intermediate BSR destinations

For zero, both magnitude words are zero. Any values selected after the zero
BSRs still feed hardware-masked shifts of all-zero words. SHLD/SHL therefore
leave H and L zero; either conditional-move path also leaves them zero. J,
T, g and the increment are all zero. R9 is explicitly cleared at `0x565f53d`.
The OR of the two original input words sets zero, so the CMOVE at `0x565f585`
replaces the otherwise arbitrary exponent base with that known zero R9.
The sign is zero. Consequently the returned bits are positive zero regardless
of either undefined BSR destination. The proof does not execute or emulate a
BSR instruction with zero input.

## Independent oracle and validation boundary

The oracle does not normalize an integer or implement the target sticky-bit
recipe. It binary-searches the ordered positive normal binary64 code space,
decodes each candidate to an exact rational, and selects the smaller exact
distance; equal distances choose the even code. The positive search endpoint
is the exact value `2^127`, sufficient for every input magnitude. Zero is
handled directly. No Python float conversion is used.

The proof supplies the relation over every signed input. The frozen finite
corpus and executed new Rust builds separately test the implementation and
compiler path; they do not enumerate all `2^128` inputs or prove target machine
code identity. Target instructions were only statically parsed/disassembled.
