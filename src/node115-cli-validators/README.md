# node115 CLI validators

This crate models two input-acceptance predicates identified in
`research/work-items/RE-012-node115-cli-command-factory/README.md`, for target
node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`:

- checked unsigned 64-bit decimal syntax, with optional leading `+`;
- exact lowercase `true` / `false` syntax.

The numeric callback is observed to return a unit-like success result; this API
does not parse or expose a number. It also does not recreate target error objects,
validator vtables, the `node-ip` grammar, address callbacks, or command parsing.
The tests cover boundary behavior implied by the evidence; they are not a new
binary comparison. No captured binary is executed.

Run `cargo test --manifest-path src/node115-cli-validators/Cargo.toml` from the
repository root.
