# Integer production correspondence — separate post-gate source phase

This document explains newly authored MIT source in
`src/node94-funding-rate-values/src/lib.rs`. It does not alter the pre-source
contract, native proof or independent expectations. The pre-source freeze is
`9549a435f609bcaed7293a0eedf7fd3961573bb0d9e07ab3b05a8effd720444b`;
the coordinator admitted it before production/client authorship. The later
source freeze and coordinator source/build gate precede production compilation.
Actual results are a subsequent phase and must not be inferred from this proof.

## Representation and rounding lemma

A finite raw word represents signed `m * 2^p`. Subnormal/zero words have
`m=fraction`, `p=-1074`; normal words have `m=2^52+fraction`,
`p=exponent_field-1075`. Thus `m<2^53` and `-1074<=p<=971`.
The sign is separate. No host floating arithmetic, bitcast arithmetic,
instruction interpreter or expected-output lookup participates in production.

For a nonzero exact dyadic magnitude `M*2^P`, let
`t=floor(log2(M))+P` and `q=max(t-52,-1074)`. `round_dyadic` rounds
`M*2^(P-q)` to the nearest integer, selecting the even integer at an exact
halfway point. If the right shift is1..127, quotient/remainder and half-unit
are exact u128 values. At shift128 the quotient is0: only a magnitude strictly
above `2^127` rounds to1, and equality selects even0. At shift>128 the value
is strictly below half a unit. A nonpositive shift is an exact left shift of
at most52 positions, yielding at most53 significant bits.

`encode` receives the rounded integer in units of `2^q`. Its nonzero width
and exponent determine the ordinary sign/exponent/fraction encoding. A carry
at `2^53` moves to the next binade. If the exponent is below-1022, q is
necessarily-1074 and the integer fits the subnormal fraction. Rounding up to
`2^52` at q=-1074 becomes the minimum normal. A result beyond exponent1023
becomes signed infinity. The largest finite value's overflow midpoint is
`(2^54-1)*2^970`; it rounds to the even next-binade significand and infinity.
The immediately lower representable value remains finite. Rounded zero retains
the mathematical sign; an exact addition cancellation separately chooses+0.

These functions are private to this bounded family. Multiplication supplies
at most106 significant bits; integer length conversion supplies at most64;
addition below supplies at most118. Their exponent arithmetic fits i32 and
every evaluated shift has a proven bound. No arbitrary-u128 public float API
is exposed.

## Addition, subtraction and zeros

`nan` selects the first raw NaN if present, otherwise the second, preserving
sign/payload and setting quiet bit51. Addition checks this before infinity.
Opposite signed infinities produce the specified negative indefinite
`fff8000000000000`; otherwise an infinity is returned unchanged. Two zeros
produce-0 only if both are negative. A single zero leaves the other finite
operand unchanged. These are the frozen nearest-even Intel SSE rules.

For nonzero finite operands, parts with exponent distance<=64 are aligned to
the smaller exponent by exact u128 shifts. Each original significand has at
most53 bits, so an aligned operand has at most117 bits; their sum has at most
118 and cannot overflow. Same signs add magnitudes. Opposite signs subtract
the lesser magnitude from the greater, retaining the greater's sign; equality
returns+0. One `round_dyadic` call then supplies the required rounding.

For exponent distance d>64, the smaller magnitude is
`<2^53 * 2^(P-d) <= 2^(P-12)`, where P is the dominant exponent.
The dominant nonzero finite word is normal: a subnormal has the minimum
possible parts exponent and cannot dominate this exponent gap. Its smaller
adjacent spacing is at least `2^(P-1)` (the predecessor at an exact power of
two is the tight case). The perturbation is strictly below half that spacing,
so both addition and opposite-sign subtraction round to the dominant word.
This also cannot cross the largest-finite overflow midpoint. Returning that
word is an exact nearest-even conclusion, not a dropped sticky-bit heuristic.

Subtraction selects and quietens NaNs *before* flipping the second sign; then
it uses addition on the finite/infinite arithmetic operands. This distinction
preserves a second-source NaN's original sign. The final family can mask some
private-operation differences through later first-source priority; private
unit tests do not imply every such difference is observable in the corpus.

## Multiplication and positive-length division

Multiplication applies NaN priority first. Zero times infinity generates the
specified indefinite; other infinities use the XOR sign. Finite magnitudes
multiply exactly in u128 (`<2^106`) and their exponent sum fits i32. The common
dyadic lemma supplies gradual underflow, ties, signed zero and overflow.

Division is deliberately specialized to a nonzero positive integer sequence
length. `round_dyadic(count,0,false)` first implements the correctly rounded
integer-to-binary64 conversion. A valid native vector satisfies
`N<=capacity<=floor(isize::MAX/8)=2^60-1` on the captured64-bit target; hence
the native signed64 conversion is positive. Values above2^53 are rounded
before division, not treated as exact real divisors. A valid safe u64 slice
supplies the corresponding bounded length on ordinary32/64-bit Rust targets.
Private count tests exercise >2^53 conversion directly; they do not fabricate
or claim execution of an impossibly allocated sample slice.

NaN sums are quieted, signed zeros and infinities are returned unchanged;
the rounded length is finite positive. For a nonzero finite sum let its
parts be `(a,A)` and the length's parts be `(b,B)`. Comparing significand
widths and then one bounded exact shifted comparison computes
`r=floor(log2(a/b))`, with `-52<=r<=52`. The result's exact top exponent is
`A-B+r`; choose `q=max(A-B+r-52,-1074)`.

The desired rounded integer is `a*2^(A-B-q)/b`. For nonnegative shift s,
the shifted numerator fits at most106 bits: s<=52-r and
`width(a)+s<=width(b)+53<=106`. Each evaluated left shift is therefore
less than128. For negative s, shift the denominator. If that denominator
would exceed128 bits, `a<2^53` proves the quotient is strictly below half
and signed zero is exact. Otherwise both numerator and denominator fit.
Integer quotient and remainder are exact; compare remainder with
`denominator-remainder` to choose above-half or exact-half without doubling
and overflowing. Ties select even quotient. `encode` handles the same
normal/subnormal boundary and carry as above. This proof uses integer
significands and division, independently of the oracle's Fraction values,
binary search over adjacent encodings and distance calculation.

## Formula and selected caller projection

The public function rejects only missing/present-empty samples as absence.
Its slice loop performs one `add` per sample in order from raw-0; there is
no reassociation, block reduction or early return on a special value.
`divide_by_count` supplies the mean. The exact captured optional defaults
are `3f1a36e2eb1c432d` and `3ff0000000000000`.

It subtracts mean from interest, and checks **both** gap and clamp for finite
classification before the first clamp. For finite words, `less` implements
numeric order by sign/magnitude, treating both zero encodings as equal.
`minimum`/`maximum` choose the second word on equality, including opposite
zero signs, preserving the native operand order. The low/high bounds are
formed from clamp and sign-XOR clamp exactly as in the frozen native proof.

The function then adds mean to the selected gap, multiplies by the optional
multiplier, conditionally clamps a finite product to captured±0.32 bits and
always multiplies by captured0.125 bits. It returns presence for every such
result, including NaN/infinity/-0. `insertion_bits` replaces only absence by
positive zero. This is the selected caller's value request, not actual map
insertion, allocation, runtime environment or settlement equivalence.

## Client and qualification boundary

`driver.rs` parses only the frozen input TSV. IDs are checked and echoed but
never influence computation. Declared field count is checked against actual
fields before allocating sample values, with a safe-slice byte-size bound.
The client accumulates successful output privately and writes only after all
input passes, so malformed records cannot leave a successful partial stream.
Allocation/IO failure behavior is ordinary host behavior, not native rollback.
No expected/provenance file, oracle, semantic label or output path is read.

Focused actual-crate tests include standalone arithmetic boundary lemmas and
public value cases; frozen corpus comparison remains the independent larger
check. The isolated harness directly links the real compiled rlib. It pins
the actual dependency-free manifest/lock/metadata graph, the complete installed
toolchain bin/lib payload and source/client bytes, rejects symlink inputs and
ancestor Cargo configuration/workspace inputs, and asserts the metadata
workspace root equals the isolated component. Two fresh physically distinct
clean roots retain raw artifact comparisons without masks. Compiled semantic
mutants run in both profiles; every claim requires a complete differing output
stream. Raw stdout/stderr and any failure are retained. Host OS/dyld and all
SDK contents are not hermetically pinned. This is host-compiled value evidence,
not captured execution, native ABI/layout/byte identity or a component gate.
