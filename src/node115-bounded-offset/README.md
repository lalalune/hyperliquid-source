# Node115 bounded-offset leaf

This dependency-free, `no_std` crate expresses the raw three-`u64` return
relation established by the complete 83-byte node #115 leaf at ELF VA
`0x45514d0..0x4551523`. Its identity is bound to SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` in the
[static evidence packet](../../research/work-items/RE-001-node115-ring-offset/README.md).

`bounded_offset` returns `(1, 0)` for a zero third word. Otherwise it computes
the wrapped offset from the first two words and returns
`(0, min(offset, third_word - 1))`. The API uses raw words because the original
Rust type, caller-wide object layout and domain meaning remain unresolved. The
name “ring” in the evidence packet is a hypothesis, not an inferred type.

The boundary vectors reproduce the packet's instruction-derived expectations.
The property test independently follows the observed compare, wrapping
arithmetic, unsigned branch and shift/subtract loop over 10,000 deterministic
`u64` triples. These tests validate the Rust relation against the static
derivation; they do not execute or emulate the captured binary, recover its
original pointer ABI, prove compiled-byte identity or close any component gate.

Run `cargo test --offline --locked --manifest-path
src/node115-bounded-offset/Cargo.toml` with Rust 1.95.0 or newer. No external
dependencies or network access are required.
