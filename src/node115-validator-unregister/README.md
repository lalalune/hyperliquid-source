# Node 115 validator unregistration state

Independent owned Rust for the nonzero/non-one subtype of `0x3c3d480` and its
follow-up `0x3c36ba0`. Actual keyed maps implement the blocking gate, missing
validator check, three removals, related-key set insertion and history-linked
record replacement. Names remain conservative where business meaning is not
established; this is a logical state projection, not native layout compatibility.

See the [evidence packet](../../research/work-items/RE-010-node115-validator-unregister-source/README.md)
for exact ordering, target identity, validation and limits. History rows are
supplied as an actual ordered collection; the implementation reads its last
key rather than accepting a precomputed latest-key result.

Run `cargo test --offline --locked --manifest-path src/node115-validator-unregister/Cargo.toml`.
