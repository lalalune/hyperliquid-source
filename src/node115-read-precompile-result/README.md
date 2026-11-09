# Node #115 ReadPrecompileResult name decoder

Models the four exact names and declaration-order tags in the EVM
`ReadPrecompileResult` visitor packet at
`research/work-items/evm-call-outcome-codec-115`. The enum type label is
observed at the enum-access call; the variant semantics come from their names
and remain inferred. Evidence is bound to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This crate covers the name-to-tag mapping and visitor success word only. It does
not implement the serializer, unknown-variant error formatting, lossy UTF-8
conversion, or the enum's owning caller.

Tests check both visitor success representations and rejection outcomes over
all 3,584 saved visitor rows. They use the committed TSV only and do not run or
emulate the captured binary. Run with `cargo test --manifest-path
src/node115-read-precompile-result/Cargo.toml`.
