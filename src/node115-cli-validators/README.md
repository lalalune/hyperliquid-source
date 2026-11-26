# node115 CLI validators

This crate models input-acceptance predicates identified in
`research/work-items/RE-012-node115-cli-command-factory/README.md`, for target
node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`:

- checked unsigned 64-bit decimal syntax, with optional leading `+`;
- exact lowercase `true` / `false` syntax;
- the complete IPv4 input for the `change-validator-profile` option `node-ip`.

The numeric callback is observed to return a unit-like success result; this API
does not parse or expose a number. It also does not recreate target error objects,
validator vtables, signer/address callbacks, or command parsing.
The tests cover boundary behavior implied by the evidence; they are not a new
binary comparison. No captured binary is executed.

Run `cargo test --manifest-path src/node115-cli-validators/Cargo.toml` from the
repository root.

The `node-ip` callback at VA `0x56546c0` skips the reader for inputs longer
than 15 bytes. Otherwise it calls the IPv4 prefix reader at `0x167ccb0` and
requires both a successful parse and zero remaining bytes. For example, the
reader consumes the address in `1.2.3.4x`; the CLI rejects the full input
and uses the literal `NodeIpParseError` at VA `0x453ab0`. The Rust callback
returns the same error text as a borrowed string. It reuses the independently
authored [prefix reader](../node115-host-ip-gates/lib.rs) through a local Cargo
dependency. It does not model ownership of the native string.

The [CLI evidence packet](../../research/work-items/node-runtime-cli-value-parsers-115/README.md)
provides the length, EOF and error-text observations. The integration test reads
the 100 frozen IPv4 rows in that packet and compares the Rust result to its
recorded callback outcomes. Run it offline from the repository root:

```sh
cargo test --locked --offline --manifest-path src/node115-cli-validators/Cargo.toml
```
