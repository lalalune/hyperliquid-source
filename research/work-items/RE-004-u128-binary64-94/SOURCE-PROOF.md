# Independently authored integer source theorem

This proof concerns `src/node94-u128-binary64/lib.rs::binary64_bits` only.
The complete native proof and root's independent proof/16,614-row authority
preceded this implementation. Original ABI and machine-code identity are not
premises of this scalar numerical projection.

Zero returns zero before any count or shift. For n>0, after j iterations of
the first loop, `probe=floor(n/2^j)` and `exponent=j`. The loop ends after
`e=floor(log2(n))` iterations, with probe1 and e in0..127. Its fixed right
shift cannot overflow, and its counter never exceeds127.

For e<=52, n<2^53, so conversion to u64 is exact. The left shift by52-e is
in0..52 and produces a 53-bit significand `q=n*2^(52-e)` in[2^52,2^53).
No bits are discarded and no rounding is required.

Otherwise s=e-52 is in1..75. `retained=n>>s` is a 53-bit integer in
[2^52,2^53). Its left shift by s exactly restores n's high bits and is at
most n, so neither that shift nor `n-(retained<<s)` overflows. The resulting
residue r lies in[0,2^s). The halfway shift by s-1 is in0..74. The predicate
`r>halfway || (r==halfway && q odd)` is exactly nearest rounding with even
tie selection. Before the increment q<=2^53-1; afterward q<=2^53, fitting u64.

The only carry case is q=2^53. Dividing q by2 through the fixed one-bit shift
and increasing e by1 represents the same rounded value at the next binade.
Now e is at most128 and q in[2^52,2^53). The biased exponent is in1023..1151;
shifting it by52 fits u64 and stays below the infinity exponent2047. Masking
off q's implicit leading bit and OR-ing its fraction produces the standard
binary64 encoding. All nonzero inputs give positive finite normal results;
the maximum integer rounds to `2^128` (0x47f0000000000000).

Thus every shift count is in bounds, every narrowing conversion is exact,
and every addition/subtraction is within its unsigned type. The source uses
no floating operator, integer division/remainder, unsafe operation, allocation
or external numerical helper. Its result matches the independent mathematical
specification for all2^128 input values. That complete argument is distinct
from finite supporting vectors and from the official132-byte correspondence.
