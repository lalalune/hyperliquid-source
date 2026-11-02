# Round helper under all four target rounding modes

The complete 113-byte body is `0x565f410..0x565f481` in node #94. All
addresses are linked ELF VAs and bind to `static.json`'s full target digest.
This is a returned-low-64-bit contract with intact code/data, valid return
stack and all SIMD floating exceptions masked. It does not reconstruct
exception flags, traps, upper XMM lanes or the callers' environment setup.

## Observed computation

The function first copies XMM0 into XMM1. The 128-bit mask at `0x2082f0`
keeps each lane's sign bit. OR with the 128-bit constant at `0x203ae0`
forms a same-sign magnitude `h = 1/2 - 2^-54` in the low lane. Both constants
are read in full and locked by the structural verifier.

`ADDSD` at `0x565f428` adds the original input in XMM1 to that signed h.
Everything after this instruction is integer/bitwise. It extracts the
rounded result's exponent E. E>1074 returns its bits; otherwise a sign-only
mask is selected for E<1023 and a fractional-clearing mask for E>=1023.
The latter mask is `~(2^(1075-E)-1)`. The test before the final mask merely
avoids moving an unchanged value. Thus the low result is exactly
`trunc(RC64(x + copysign(h,x)))`, where RC64 is the target binary64 addition
mode. The body has no calls and only two internal conditional branches.

The [Intel architecture manual](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366521.pdf)
defines the four MXCSR.RC modes in sections 4.8.4 and 10.2.3.2; Table E-1
specifies NaN results for masked scalar addition. Sections 10.2.3.3–4 define
FTZ and DAZ. These architecture rules are premises of this static derivation,
not hardware observations collected by this packet.

## Finite magnitudes below 2^52

Write delta=2^-54, a=abs(x), and let N be a positive integer. The boundary
for returning magnitude N is A=N-1/2. The exact sum at this half boundary is
N-delta. For a predecessor of A, the distance below N is larger.

At A=1/2, pred(A)=A-delta. Therefore pred(A)+h=1-2^-53=pred(1), which stays
below 1 even when rounded upward. At A itself, A+h=1-delta is exactly the
midpoint between pred(1) and 1, and nearest-even chooses 1. Downward-magnitude
rounding chooses pred(1), whose truncation is zero.

For integer N>=2 with A<2^52, the spacing at pred(A) equals the spacing
immediately below N and exceeds delta. Thus pred(A)+h lies more than one
such spacing below N. Neither nearest nor upward-magnitude rounding can
cross N from that predecessor. At A itself, N-delta is closer to N than to
pred(N), so nearest and upward-magnitude rounding select N. Downward-magnitude
rounding selects pred(N), whose truncation is N-1. Every input above A has
an exact sum above N. Monotonicity of addition and each rounding mode then
establishes the boundary for every representable input between adjacent
halves, not just the frozen witnesses.

Consequently, for a<2^52, nearest-even **addition** yields ordinary
half-away-from-zero integer rounding. Directed addition toward increasing
magnitude has the same integer result. Directed addition toward decreasing
magnitude instead rounds exact halves toward zero. For a<1/2 every result
truncates to signed zero. The Rust E=1022 arm handles [1/2,1) explicitly;
its E>=1023 arm compares the fractional bits to exactly half an integer unit.

Increasing magnitude means RC=toward-positive for positive x, or
RC=toward-negative for negative x. Decreasing magnitude includes toward-zero
and the opposite directed mode. This sign dependence is retained explicitly.

## Large finite magnitudes and exceptional inputs

For a>=2^52, spacing to the next representable magnitude is at least 1,
while 0<h<1/2. Nearest-even and decreasing-magnitude addition retain a.
Increasing-magnitude addition selects the next representable value, whose
bits are the finite input word plus one. For the largest finite input this
is infinity. Every finite result here is already integral, so truncation
does not undo the increment. A blanket early return for large inputs would
therefore be wrong for two directed-mode/sign combinations.

Infinities remain unchanged. Only the original x operand can be NaN, since
the constructed h is finite. Masked ADDSD preserves a quiet NaN's payload
and sign, and sets the quiet bit of a signaling NaN. The later exponent
guard returns it unchanged. Unlike a purely bitwise truncation leaf, this
helper does not preserve a signaling NaN bit-for-bit.

DAZ affects only subnormal x; with either DAZ setting, the signed sum has
magnitude close to h and truncates to the same signed zero. Every finite
sum has magnitude at least h, which is normal, so FTZ cannot affect it.
These statements concern output bits only, not denormal/inexact flags.

## Rust bounds and independent oracle

The only variable Rust shift is reached for E=1023..1074, giving counts
1..52. The largest negative integer-rounding result is
`0xc330000000000000`, so adding one unit cannot overflow u64. The separate
large-input increment operates only on finite inputs, whose largest signed
encoding is `0xffefffffffffffff`; its successor fits u64. No unsafe code,
host floating operations or global floating-state changes are used.

The Python oracle constructs the exact same-sign sum as an arbitrary-precision
integer divided by a power of two. It rounds that rational to a 53-bit
significand according to RC, then mathematically truncates and exactly encodes
the integer. It does not apply the Rust half-boundary shortcut. Both DAZ
interpretations are compared during fixture regeneration. This is a second
mathematical formulation of the static contract, not captured instruction
execution, emulation, or proof of compiler correctness.
