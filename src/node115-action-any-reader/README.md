# node115 MessagePack `deserialize_any` model

This crate models the node #115 `rmp_serde` value-level `deserialize_any`
state machine from `research/work-items/RE-010-action-msgpack-struct-any-115`.
Its target SHA-256 is
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The implementation covers marker dispatch, length reads, string UTF-8 fallback,
binary flag selection, extension/map/sequence depth handling, visitor outcomes,
length mismatch, and observable input/depth state. Callee results and container
visitor mutations are explicit inputs. Visitor internals, the `any` helper,
surrounding Action decoders, and exact call-sequence reconstruction are outside
this crate's contract. Reserved non-Marker table entries are represented as
unreachable because the target routes them to `ud2`.

Run `cargo test --manifest-path src/node115-action-any-reader/Cargo.toml` from
the repository root. The test compares exact result payloads and deserializer
state for all 7,925 committed case rows and checks their recorded C1 verdicts.
The evidence packet reports 25,783 model cases and 77,349 target runs across
three copies with zero mismatches; this crate does not claim it independently
re-ran those target comparisons. It never executes a captured binary.
