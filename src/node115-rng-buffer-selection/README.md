# Node #115 buffered RNG scheduling kernel

Independently authored MIT `no_std` Rust. It reconstructs the buffered-u32 draw,
entropy/refill selection and reseed policy field transitions observed in Linux
x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
It does not obtain entropy or implement CPU dispatch. A caller that has already
established that native dispatch selected the four-block fallback may use
`RefillRequest::complete_four_block_fallback`; accelerated alternatives and
provider behavior remain separate boundaries.

`begin(&mut State, observed_epoch)` consumes a buffered u32 when available;
otherwise it returns an owned pending entropy or refill request. An entropy
request accepts a caller-supplied 32-byte seed or normal failure result.
Success installs seed32 followed by sixteen zero bytes; normal entropy failure
retains the old key state. Both paths write the observed epoch before the
checked base-budget subtraction. Overflow therefore retains those earlier
writes, while leaving the previous remaining budget and cursor untouched.

A refill request exposes the exact policy state and native argument six.
`complete(RefillOutput)` remains available for externally supplied output.
The bounded `complete_four_block_fallback` adapter maps the 48 state bytes as
eight little-endian key words and four tail words, applies the existing
#115-bound four-block fallback, installs its advanced counter and 64 output
words, returns word zero, and leaves cursor one. It must only be used after the
fallback branch has been established; it does not choose CPU alternatives.
Dropping a request does not synthesize output or roll back state. The probe's
arbitrary synthetic boundary fixtures are not RNG evidence.

TLS/reference lifetime, entropy provider, error-box allocation failure,
accelerated CPU paths, native layout and panic ABI remain outside this safe
logical API. The complete evidence, pre-Rust frozen expectations, compiled
mutant controls and limitations live in
`research/work-items/RE-012-rng-buffer-selection-115` and
`research/work-items/RE-001-node115-rng-fallback-compose`.

```sh
cargo +1.95.0 build --offline --locked --manifest-path src/node115-rng-buffer-selection/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-rng-buffer-selection/Cargo.toml
cargo +1.95.0 test --offline --locked --manifest-path src/node115-rng-buffer-selection/Cargo.toml
```
