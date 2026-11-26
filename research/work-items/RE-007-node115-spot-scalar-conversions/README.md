# Scalar spot-metadata conversions on node 115

The Rust crate `src/node115-spot-scalar-conversions` reconstructs two distinct 64-bit conversions. The earlier [token decimal packet](../exchange-token-decimal-scaling-115/README.md) and [four-limb implementation](https://github.com/lalalune/hyperliquid-source/pull/7073) establish prior work on signed exponent scaling. Here the exponent is the checked unsigned difference between bytes +0x49 and +0x48 of a 0x158-byte token metadata record. Both functions stop for an invalid selector or a power outside the u64 range. The product path first resolves the token index at +8 of a 32-byte pair record.

Target `artifacts/node/115/hl-node` is 105896032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Coordinates are image virtual addresses. All retained instructions are cited context.

## Results and consumers

* `0x46aa2e0` computes value times scale divided by divisor. If multiplication overflows, it divides the original value by the divisor first and retries the multiplication. A zero divisor or a second overflow returns zero. A successful zero quotient becomes one, including a zero input. At `0x3bf5c33..0x3bf5c52` the caller supplies 10^12 as the value, the stack token selector and divisor, then saves the returned word.
* `0x3c201e0` computes the two operands' product divided by scale. On product overflow it first tries exact divisibility of the left operand, then the right. When neither divides evenly it truncates the larger operand by the scale and multiplies by the smaller. It returns zero on fallback product overflow and retains zero on a zero quotient. The caller at `0x3c4a15c..0x3c4a17b` supplies its resolved word, second operand, original pair index and metadata base, then directly returns the result. The neighboring miss branch supplies its own value through the callee at GOT `0x64e7168`.

The host exposes bounds and scale errors as a typed stop at native error frontiers. It models returned scalar values on ordinarily returning diagnostic paths. Allocation, logging side effects, record population, and the economic units attached to each argument are outside this interface.

## Verification

```sh
python3 research/work-items/RE-007-node115-spot-scalar-conversions/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-spot-scalar-conversions/Cargo.toml
```

The verifier reads the original ELF and checks its digest, function bounds, complete instruction transcripts and relocation targets. It uses Capstone 5.0.7 and pyelftools. The Rust suite compares both results in 3,701 deterministic operand pairs with Python arbitrary-precision expectations (7,402 result comparisons). Separate cases cover metadata stop order, overflow, shared-token indexing and the two distinct zero policies. At scale 10 the native ratio fallback for u64::MAX and divisor 2^63+1 returns 10; unbounded multiplication first would return 19. The product test uses two nondivisible operands whose product overflows, and demonstrates the difference when truncation moves ahead of multiplication. No captured program was executed.
