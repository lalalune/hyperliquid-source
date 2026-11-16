# Node115 raw decimal96 conversion

Converts an already parsed 96-bit coefficient, decimal scale 0–28 and sign into
binary64 using the selected native operation order. It extends the existing
short fee-trial converter's u64/scale≤16 domain; it does not parse strings or
replace that crate.

The fractional path splits integer quotient and remainder before converting,
then rescales, rounds and divides in the native order. It can differ from a
single floating division, and from a correctly rounded exact decimal value.
Raw negative zero becomes positive zero at scale 0, but remains negative zero
at scales 1–28. The constructor rejects unsupported scales as an adapter guard.

See `research/work-items/RE-017-node115-decimal96-source` for exact target
bindings, predecessor credit and the independent rational fixture generator.
No native layout, invalid flag behavior, parsing grammar, allocation behavior,
upstream factor acceptance or root/certificate correctness is claimed.
