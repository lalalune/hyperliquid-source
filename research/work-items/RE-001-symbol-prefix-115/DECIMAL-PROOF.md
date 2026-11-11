# Arithmetic obligations of the selected formatter

This is a manual arithmetic argument supported by operand-bound integer checks,
not machine-checked whole-ISA, compiler or resolver equivalence. The original
control/data binding and finite instruction corpus remain separately necessary.

For unsigned x<=X, M=ceil(2^k/d), and delta=d*M-2^k, if
`X*delta < 2^k`, then `floor(x*M/2^k)=floor(x/d)`. Indeed x/d has a fractional
part at most (d-1)/d, while the positive approximation error is strictly less
than1/d. `decimal-proof.py` checks the sufficient bounds against actual
instruction immediates for:

- d10000,k75,M0x346dc5d63886594b,X=2^64-1,delta432;
- d100,k19,M0x147b,X9999,delta12;
- d25,k17,M0x147b,X249,delta3.

The first native unsigned MUL/high-word/shift therefore forms the exact
quotient by10000. The subsequent low32 subtraction also yields the true
remainder0..9999: equality modulo2^32 and that small remainder give the same
value. Multiplication by5243 of a value at most9999 fits32 bits; the second
bound divides that remainder by100. Two indexes in0..99 then select the
actual two-character digit-pair table. MOVD/PINSRW/store assemble those four
ASCII bytes in order. No floating conversion or locale participates.

The loop continues when the pre-division value exceeds9999999. Thus the
remaining prefix after the last full four-digit group is at most999. Its
final division is floor(floor(x/4)/25)=floor(x/100), implemented by the third
bound (x/4<=249). The retained lower pair is again in0..99. A nonzero remaining
hundreds digit is emitted separately. Original zero emits one digit; otherwise
the zero prefix above a complete two/four-digit group is skipped. The result
has1..20 significant digits, with no leading zero except for zero itself.

The scanner's unchecked short loop handles at most16 digits, so induction
bounds its value by10^16-1<2^64. The long loop checks unsigned multiplication
overflow and addition carry on each digit. Leading zeros do not need a length
cap, while each nonzero-overflow case rejects. A sign-only input is rejected
before the otherwise unreachable empty-after-sign formatting block. The Rust
source uses one checked loop for both native lengths and a fixed-array decimal
conversion; it preserves the logical observation without imitating code bytes.

This closes the numeric formatting dependency for the stated call-free prefix.
It establishes no allocator success, original lifetime/type identity, following
memcmp outcome, metadata identity or whole-function replacement. The separate
4072-case finite correspondence and real byte controls cover the actual selected
instructions; all component completion gates remain false.
