# Five-word masked-top coefficient combination

This packet covers node94 `[0x565e960,0x565ea92)`, all 306 bytes and 93
instructions. Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It does not claim the neighboring 438-byte helper at `0x565e7a0`, the 363-byte
helper at `0x565eaa0`, the caller's algorithm, or the operands' meaning.

## All-word relation

Let B=2^64. Decode each input's five qwords, little endian, as the unsigned
integer X in `[0,B^5)`. For a raw coefficient c in `[0,B)`, let

* s=c when c<B/2, otherwise s=c−B;
* m=|s|, so 0≤m≤B/2, including s=−2^63;
* Y=X when s≥0, otherwise Y=(−X) mod B^5;
* L=Y mod B^4 and T=floor(Y/B^4).

The contribution is

`P(X,c) = (m*L − (T AND m)*B^4) mod B^5`.

For inputs A,Bval and coefficients c,d, the five output qwords are the
little-endian decomposition of

`S = (P(A,c)+P(Bval,d)) mod 2^320`.

Every 320-bit input and every raw coefficient is admitted by the value API.
No sign-extension condition on either fifth word is assumed. The fifth word
is a bit mask: it is not an unrestricted fifth multiplication limb.
For example, input `[0,0,0,0,1]` and coefficient 1 contribute `−2^256 mod 2^320`,
while input `[0,0,0,0,2]` and coefficient 1 contribute zero. Ordinary 320-bit
multiplication would give positive 2^256 and 2^257 respectively.

Even a sign-extension-looking input is not sufficient to replace this formula
universally. `[0,0,0,0,2^64−1]` with coefficient−1 transforms into top word 1 and
low 256 bits zero; its contribution is still `−2^256 mod 2^320`. The claim here retains
the observed AND, without guessing an upstream range invariant.

## Sign-conditioned transform and products

The first five loads obtain qwords 0..4 before any arithmetic. SAR of the raw
coefficient by 63 produces the all-zero or all-one mask according to its sign.
XOR followed by addition of the mask's negation gives the unsigned magnitude;
for rawMIN this is 2^63, so no signed absolute-value overflow is needed.

The same XOR mask is applied to all five input words. ADD at the low word and
four ADCs propagate the initial 0/1 through all 320 bits. These operations give
X for a nonnegative coefficient and (−X) mod 2^320 for a negative coefficient.
When X=0 and the coefficient is negative, the carry out of the fifth word is
discarded; the transformed value is exactly zero. No correction to an invented
negative-zero value is permitted. None of the later MULs consumes that carry.

Write Y's lower words as y0..y3. Four unsigned MULs compute yi*m. The high half
of each preceding product is added to the following low half; any carry from
that ADD increments the following high half. Consequently the first four
product words and final high carry are exactly those of m*L. If m>0 and a
previous carry is at most m−1, then

`yi*m + carry ≤ (B−1)*m+(m−1) = B*m−1`.

Its high half is again at most m−1. The first carry is zero, so induction proves
this bound for all four products. For m=0 all words/carries are zero. Rust's
u128 temporary is at most 2^127−1 under the recovered coefficient bound, and
cannot overflow even with overflow checking enabled.

Before the fourth MUL, the transformed fifth word is ANDed with m and negated
moduloB. The ADC after that MUL adds its high half and the low-half addition's
carry. Thus the final high word is

`floor(m*L/B^4) − (T AND m) mod B`,

which proves the contribution equation. The fifth word is never multiplied by
m. The first contribution occupies R8–R11 and RBP. The second uses R12–R15 and
RCX, with the same operations and widths.

Five ADD/ADCs then add these contributions moduloB^5. Carry out of the high
word is discarded. Each Rust sum temporary is at most 2B−1, well within u128.
The five ordered stores write the sum's words 0..4 at incoming RDI+0,8,16,24,32.

## Exact final register observations

For the second operand, retain Y2, m2, P2=P(Bval,d), and

`W = (floor((Y2 mod B^4)/B^3))*m2`.

W is the raw final 64×64 product, before the preceding limb's carry is added.
Let S0..S4 be the output words and Q0..Q4 the words ofP2. At the final REP RET:

| Register | Full u64 value |
| --- | --- |
| RAX | W modB |
| RDX | floor(W/B) |
| RBX | m2 |
| RCX | Q4 |
| RBP | S4 |
| R8,R9,R10,R11 | S0,S1,S2,S3 |
| R12,R13,R14,R15 | Q0,Q1,Q2,Q3 |

The final MUL overwrites RAX/RDX. Subsequent ADD, ADC and MOV instructions do
not write them. In particular RAX is not Q3 after its carry addition, and RDX
is not the corrected high wordQ4. The contribution sum changes only the first
set of five accumulator registers. RDI/RSI are unchanged; their numeric values
are not synthesized by the value API. Flags, RET/stack/CET state and unmodified
registers are outside this projection. This leaf uses registers normally
described as callee-saved without a conventional save/restore sequence; the
new Rust functions do not claim the original native calling convention.

## Memory order and arbitrary data aliases

The body reads the first 40 bytes through incoming RSI, computes their
contribution, reads the following 40 bytes, computes the second contribution,
adds, then performs five eight-byte stores. There is no store before all ten
input qwords have been read. Therefore each input value comes from the entry
image, even when the output partially or wholly overlaps either input or
crosses the boundary between them. The output stores address distinct adjacent
qword ranges on the admitted nonwrapping image. Every byte outside their 40-byte
union is preserved. No input alignment premise is added.

`combine` is a total value function for all ten words and both coefficients.
`apply_image` supplies a safe finite-image adapter: `source` and `destination`
are offsets in one ordinary, stable byte image, never native pointers. It
requires the complete 80-byte source and 40-byte destination ranges to fit.
Their host usize conversions and ends use checked arithmetic before indexing;
source+8i+8 and destination+8i+8 then stay within those checked ends. Conversion
of exactly eight bytes to an array cannot fail after these checks. All input
words are snapshotted before the first output write.

The adapter corresponds to original normally returning calls whose reached
source and destination ranges are represented by this nonwrapping image under
a common base and whose effective address formation does not wrap. It does not
claim every possible raw pointer bit pattern. Pointer provenance, mapping,
concurrency, races, volatile/MMIO observations, exceptions, stack/control
aliases and native ABI integration are outside the model. Arbitrary aliases
among the represented data bytes are admitted.

`None` is a new refusal for an unrepresentable finite-image span, not an original
return or recovered fault. Both spans are checked before mutation; every refusal
preserves the complete image. Checking the output span early is valid for this
successful-return projection and the separately specified refusal API; it does
not assert an original fault/access order on invalid addresses.

## Static closure and independent expectations

The complete body, actual unique FDE, shared CIE and 14 following alignment bytes
are independently bound. The padding consists of NOP encodings, not part of
the 306-byte function. The body is straight-line, has no calls, branches,
RIP-relative operands or static data dependency, and ends with REP RET.

The exact .text E8 scan finds 20 candidate calls, all independently qualified
instruction boundaries in the complete caller `[0x565df20,0x565e78b)` (2155
bytes). E9/EB scans find none. All 80,300 RELA records are scanned for naming
addends and full-width overlapping writers to the body, padding and retained
caller. There are no naming addends or such writes. This is not a complete
indirect-reference census. Retaining the caller establishes sites/argument
context only, not reconstruction of its behavior.

The pre-Rust oracle forms whole 320-bit integers, applies a signed whole-integer
transform, calculates one arbitrary-precision low 256-bit product and the masked-top
correction, and projects quotient/remainder words only at the end. Its memory
result uses immutable byte concatenation. It does not import Rust or implement
the MUL/ADC instruction sequence. The Rust uses five-word complement/carry,
four bounded u128 products and five bounded word additions. Their equivalence
for every admitted input follows from the preceding argument, with the frozen
finite corpus providing additional executable qualification.

The corpus covers every operand bit rank with predecessor/exact/successor
values; every coefficient bit rank and signed direction; zero, MIN and maximum
magnitudes; arbitrary fifth-word masks; dense unaligned output aliases and
source/destination endpoint refusals. Only newly authored Rust is executed.
No target binary, captured instruction sequence or emulator is run, and no
compiled-byte, original-ABI or whole-node equivalence is claimed.
