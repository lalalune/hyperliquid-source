# Node #115 EVM transaction-type name decoder

Models the five exact name-to-tag matches and visitor success words from
`research/work-items/evm-tx-type-name-codec-115`. The packet binds the evidence
to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The enum's source-level type and EIP semantics are inferred. This crate covers
only visitor name matching and success encodings; it does not implement the
signed-transaction envelope serializer, unknown-variant error handling, or
payload serializers.

Tests compare all eight visitor bodies over the 16,184 saved rows, checking
accepted names and success values while treating the helper-specific error
payload as out of scope. They read committed evidence only and do not execute
or emulate the captured binary. Run with `cargo test --manifest-path
src/node115-evm-tx-type-names/Cargo.toml`.
