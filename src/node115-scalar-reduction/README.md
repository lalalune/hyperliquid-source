# Node #115 scalar reduction

Independently authored, dependency-free Rust for the value contract of the two
285-byte helpers at ELF VAs `0x6321680` and `0x6330f50` in node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The input is a big-endian 32-byte integer. The result contains four least-first
u64 limbs of its residue modulo the observed secp256k1 order and a Boolean
indicating that the original input was at least that order. Zero is accepted.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-scalar-reduction/Cargo.toml
python3 research/work-items/RE-001-node115-scalar-reduction/build.py
```

The [evidence packet](../../research/work-items/RE-001-node115-scalar-reduction/README.md)
contains authenticated instructions, seven static solver checks, an independently
checked 281-row corpus, and binary/source corruption controls. Tests execute only
the new Rust. The original pointer ABI, overlapping buffers, optional raw pointer
writes, return-register contents and surrounding signature/recovery behavior are
outside this safe value API. No timing, compiled target-byte identity or
full-component completion claim is made.
