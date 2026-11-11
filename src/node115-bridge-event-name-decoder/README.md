# Node #115 bridge event-name decoder

Implements the six exact event-name matches and the two observed success
representations from `research/work-items/bridge-event-name-codec-115`. The
evidence is bound to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`Node115BridgeEvent` is descriptive; the event meaning is inferred from the
names and its Rust type name is not recovered. The model does not implement
unknown-variant error formatting, lossy UTF-8 conversion, allocation/free, the
event payloads, or the enclosing bridge stream.

Tests validate acceptance and both success return encodings across all 49,360
saved visitor rows. Error rows are checked as errors; their error text and
ownership details are intentionally outside the model. Tests use only the
committed TSV and do not run or emulate the captured binary. Run with `cargo test
--manifest-path src/node115-bridge-event-name-decoder/Cargo.toml`.
