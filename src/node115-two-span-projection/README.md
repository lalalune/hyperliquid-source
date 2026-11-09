# Node115 two-span projection leaf

This dependency-free, `no_std` crate expresses the raw four-word relation
established by the complete 114-byte node #115 leaf at ELF VA
`0x152e360..0x152e3d2`. Its identity is bound to SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` in the
[static evidence packet](../../research/work-items/RE-001-node115-two-span-projection/README.md).

`project` takes the four observed input words `(C, B, H, N)` and returns the
four observed output words. It preserves the zero-count branch, the single
conditional normalization, unsigned split comparison, stride-80 arithmetic,
and modulo-2^64 behavior. These labels describe packet coordinates only; the
original source type, owner, caller domain, and any ring interpretation remain
unresolved. Its path is listed under foundation only as a work-allocation
choice; this does not identify the original component.

The boundary vectors come from the packet's decoded-operation model. A second
test compares 10,000 deterministic `u64` inputs against a separately written
transcription of the observed branch relation. These validate the Rust
relation against static evidence; they do not execute or emulate the captured
binary, recover the original output-pointer ABI, prove compiled-byte identity,
or close a component gate.

Run `cargo test --offline --locked --manifest-path
src/node115-two-span-projection/Cargo.toml` with Rust 1.95.0 or newer. The crate
has no external dependencies.
