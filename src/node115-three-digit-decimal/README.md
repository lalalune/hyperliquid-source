# Node #115 three-digit ASCII value

This dependency-free `no_std` Rust crate independently implements the value
relation established by the static evidence packet for Linux x86-64 node #115,
ELF SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`parse_three_digit_ascii` returns the integer represented by exactly three
ASCII decimal bytes when the first byte is `1` through `9` and the other two
are `0` through `9`. It returns zero for every other length or byte sequence.
The target computes the same result in EAX. The descriptive Rust name and safe
slice API are new; they are not claimed as the original source name or ABI.

The complete body is 85 bytes at `0x179b360..0x179b3b5`, with no calls or
indirect dispatch. The instruction walk and arithmetic proof are in
[`research/work-items/RE-001-node115-three-digit-decimal/README.md`](../../research/work-items/RE-001-node115-three-digit-decimal/README.md).
One direct caller checks AX and stores the result, but its larger meaning and
input ownership remain unresolved. No protocol type or field is inferred.

Tests cover all 900 valid values, non-three-byte lengths, and all 16,777,216
possible three-byte input combinations against the instruction-derived value
relation. This exhaustive logic check does not execute or emulate the captured
binary and is not a whole-node equivalence claim.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-three-digit-decimal/Cargo.toml
cargo +1.95.0 build --offline --locked --manifest-path src/node115-three-digit-decimal/Cargo.toml
cargo +1.95.0 build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-three-digit-decimal/Cargo.toml
```

The implementation is independent work under the repository MIT license. No
captured code, imported implementation, network, or live chain is involved.
