# Node #115 final LZ4 literal encoder

Independently authored MIT, dependency-free `no_std` Rust for the final-literals
helper at ELF VA `0x477f750..0x477f8ba`, including its append contract at
`0x477e5c0..0x477e6d4`. Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`encode(input, anchor, end, sink, &mut used)` appends a token, any literal-length
extension bytes, then the selected literal slice. Token/extension writes remain
in the sink on failure. Literal copy capacity is checked as one operation;
insufficient capacity never copies a partial literal slice. A 15-byte literal
slice requires `f0 00` before its bytes: the zero extension is mandatory.

This is a safe logical API. `Domain` rejects invalid Rust slice descriptors
before native semantics begin; native unchecked pointer ABI, panic payloads,
unwinding/catchability and fault-time grouped stores are not reproduced.
`Anchor` maps native checked-subtraction failure; the other errors identify
which output stage failed. The input and output cannot alias in this API.
No complete LZ4 compressor or node integration is claimed.

Full static evidence, independently frozen expectations, actual compiled-mutant
qualification and limitations: `research/work-items/RE-012-lz4-literal-encoder-115`.
The probe executable reads six decimal fields per line: source size, anchor,
exclusive end, sink capacity, initial used length, payload seed. It reports
status, resulting length and the complete output buffer in hex, including
unchanged prefix/suffix. It runs only newly authored Rust, never the capture.

```sh
cargo +1.95.0 build --offline --locked --manifest-path src/node115-lz4-literal-encoder/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-lz4-literal-encoder/Cargo.toml
```
