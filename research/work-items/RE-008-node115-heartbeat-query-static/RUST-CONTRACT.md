# Frozen Node115 heartbeat classification contract

Task RE-008. Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All native addresses are unrebased ELF virtual addresses.

The selected per-row body is `0x5a30130..0x5a305da`, 1,194 bytes, SHA-256
`9b2e1d41364bbe9cb2cd815e9d1b2d85cb2b5b06aefdc21bf68ef55098f74bda`.

The safe classification API receives a found/missing result, numerator,
denominator, configured ratio threshold, one unnamed configuration byte as a
boolean, and the already-computed age. Its selected normal-return order is:

1. missing lookup -> tag 0;
2. denominator ordered zero -> ratio is positive zero without reading the
   numerator;
3. negative or NaN denominator -> a diagnostic path, represented as a safe
   error rather than a normal tag;
4. otherwise divide and sanitize using the observed raw-bit filter:
   positive finite values and signed zeros are retained; negative nonzero,
   NaN and infinity become positive zero;
5. ratio ordered greater than the configured threshold and configuration byte
   zero -> tag 2 with the ratio;
6. otherwise age ordered greater than 180.0 -> tag 1 with the age;
7. otherwise -> tag 3 without a payload.

The safe API does not claim the original floating-point exception state,
logging side effects, map representation, time-source helper, output padding,
panic behavior or wire format. The configuration byte remains unnamed.
