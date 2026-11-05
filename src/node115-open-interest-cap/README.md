# Node115 open-interest cap projection

This dependency-free `no_std` component recovers the conditional decision and
formatting arguments of the complete node115 helper `0x447c620..0x447c7c4`.
Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The [evidence packet](../../research/work-items/RE-007-node115-open-interest-cap/README.md)
binds its full body, caller, constants, relocations and unresolved dependencies.

`project` accepts supplied signed sum operands and a multiplier, an unsigned
key, a raw selector byte and the context word observed after any addition
diagnostic. It reports the ordered diagnostic requests and either the local
sentinel write or the three formatting arguments. It does not invoke callbacks,
format strings, allocate a result or reproduce the original ABI.

On addition overflow, the sum saturates toward signed maximum and selector 0 is
requested before multiplication. Negative multipliers and either signed
multiplication overflow select formatting with
positive zero. Valid products use two signed thresholds: the lower may request
selector 1; the higher chooses the format request instead of the sentinel.
A negative representable product is below both thresholds. The original
selector byte is preserved, including values outside 0/1.

The context input is a later observation: using an entry snapshot requires the
earlier callback to preserve that field. Continuation past diagnostic requests
also requires callbacks to return and preserve the native saved inputs/output.
Floating formatting arguments preserve separate integer conversion and division
rounding. Comparison with the target assumes nearest-even rounding and a masked
precision exception, e.g. MXCSR 0x1f80, preserved by preceding callbacks. This
component does not project floating status flags or nonstandard rounding modes.

Negative second operands are refused safely with `NegativeAddend`. This is a
new host admission check, not the original error enum: that native branch
reaches an unwrap callback without an in-body return continuation. Neither
callbacks nor their panic behavior are executed here.

Build/test with the installed Rust 1.95.0 toolchain and no downloads:

```sh
export PATH="$(dirname "$(rustup which --toolchain 1.95.0 rustc)"):$PATH"
cargo test --offline --locked --manifest-path src/node115-open-interest-cap/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-open-interest-cap/Cargo.toml
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-open-interest-cap/Cargo.toml
```

Target-grounded boundary expectations are manual static relations and independent
exact arithmetic, not executions or emulations of the captured node. Host tests
and a Linux-target library build do not establish target behavior or machine-code
identity. Collection lookup, whole clearinghouse policy and all full-scope gates
remain unresolved.
