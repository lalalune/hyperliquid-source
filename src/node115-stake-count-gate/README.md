# Node115 two-collection stake/count gate

Independent Rust for the normal logical return path of linked ELF VA
0x28aa050..0x28aa36e, bound to node115 SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The first source map supplies the keys for a saturating weighted test.
Only after that test passes does the caller collect the second source map
and apply the independent count-fraction test. The two key sets cannot be
substituted for one another.

evaluate uses safe key projections, an immutable weight map and member set.
It saturates both weight sums, uses the strict wide-product comparison, keeps
the native zero-fraction arm, and retains ordered floating-point comparison.
The first temporary is dropped before the second is constructed.

This is a logical value interface. It is not the original ABI or a parser for
native map memory. Physical traversal, source-map validity, allocator/panic
behavior, original type names and higher protocol eligibility remain separate
obligations. No network-node, gate, captured execution or byte-identity claim
is made. New code is independently authored under MIT; no unlicensed inferred
source or arbitrary external dependency is used.

The evidence packet records the complete native ranges, the existing
validator-stake analysis, observations, inferences and limits. The frozen
predictions were written before this Rust source; they are static predictions,
not captured execution results.

Run from the repository root with the pinned compiler:

    cargo test --offline --locked --manifest-path src/node115-stake-count-gate/Cargo.toml
    cargo test --offline --locked --release --manifest-path src/node115-stake-count-gate/Cargo.toml
