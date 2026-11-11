# Node #115 abstraction-kind name decoder

Implements the seven exact byte-string matches documented in
`research/work-items/RE-015-abstraction-kind-codec-115`. The packet binds the
observations to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` and records
five visitor bodies: three return a tagged word and two return the enum tag.

`Node115AbstractionKind` is a descriptive model name, not a recovered Rust type
name. Unknown-variant error construction, serializers, callers, and the enum's
application meaning are outside this model. The packet's Rust-level visitor
interpretation remains an inference.

Tests compare the byte matcher and both return encodings with all 37,640 saved
visitor outcomes in the committed TSV. They do not run or emulate the captured
binary. Run with `cargo test --manifest-path
src/node115-abstraction-kind-decoder/Cargo.toml`.
