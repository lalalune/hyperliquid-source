# Node115 asset metadata JSON encoder

RE-005 serialization with an RE-012 API lead. This real isolated Cargo package
implements the ten-field logical record selected by the Node115 writer
at0x2f186b0. It does not claim the complete info endpoint, original Rust layout,
allocator, native error pointers or whole-node equivalence.

Four fields are always present, in order: szDecimals, name, maxLeverage,
marginTableId. False onlyIsolated/isDelisted, Normal marginMode, Disabled
growthMode and absent time/fee values are omitted. Remaining fields retain
their native order. Names preserve valid UTF-8 and use the observed JSON escaping.
The fee scalar is quoted, uses inferred fixed precision10, retains one fractional
zero and normalizes negative rounded zero. Nonfinite formatting follows the
pinned Rust standard formatter. Callback/descriptor evidence and the
unrecovered captured dependency revision remain distinct.

Timestamp and timestamp_text are unchanged MIT source from commit
255cb2ccd9c9443c9bb5745f04ecc1c73627b10b, retained with its original manifest,
source, tests and license under research/imported/. This is a real path
dependency, not an inferred original Cargo graph. No timestamp reconstruction
credit is added. A present raw timestamp must have a nonzero packed word and
remain inside that library's documented raw-integer profile. Its local profile
error is not a recovered native Result. Panic/unwind and partial-output
failures remain unclosed.

Build/test with installed Rust1.95.0, keeping Cargo cache and target output
in operator-owned storage:

    cargo test --offline --locked --manifest-path src/node115-asset-metadata-encoder/Cargo.toml
    cargo fmt --manifest-path src/node115-asset-metadata-encoder/Cargo.toml --all -- --check

The integration test consumes223 frozen whole messages:144 complete canonical
omission-policy combinations,54 binary64 cases, Unicode/control names,
integer fences and timestamp boundaries. Expectations were frozen before this
metadata Rust source existed. Rational binary64 arithmetic and standard JSON
encoding supply a separate reference. These are derived expected messages,
not captured runtime outputs.

See research/work-items/RE-005-asset-metadata-encoder-115 for target identity,
observations/inferences/unknowns and actual validation results.
No component gate or byte-credit change is requested.
