# Node #115 oracle outcome-kind visitor

This dependency-free `no_std` Rust leaf implements the exact-name and tag
behavior of the node #115 oracle outcome-kind visitors. The names are
`StandaloneOutcome`, `Question`, and `QuestionOutcome`, with tags 0, 1, and 2.
The tagged result word is `0x09 | (tag << 8)`. Unknown byte input preserves
valid UTF-8 and uses replacement decoding for invalid UTF-8, matching the
observed byte-visitor path.

The implementation is bounded to those visitor semantics. The source-level
enum identity is an inference from the target's names and pool; serde error
construction, JSON slice readers, scanner escape behavior, callers, and the
enum's containing record are not implemented here. It makes no component
completion or byte-equivalence claim.

## Target evidence and checks

The behavior is bound to Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The
static packet
[`risk-outcome-kind-codec-115`](../../research/work-items/risk-outcome-kind-codec-115/README.md)
interprets all six original visitors and records 2,333 input vectors. Its
`visitor-cases.tsv` marks every vector as matching the original-byte
interpreter and records the result of each visitor copy. The Rust test consumes
that same file and compares every recorded status and result word across all
six visitor copies, plus the byte visitor's unknown-value decoding. The
captured executable is never run.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-oracle-outcome-kind/Cargo.toml
python3 -m unittest tests.test_risk_outcome_kind_codec_115
```

The first command tests the Rust port against the retained target-derived
vectors. The focused Python test regenerates and checks the underlying static
interpreter evidence with the full target digest check before parsing. It
interprets selected original instruction bytes and never runs the captured
executable. `make verify` checks the packet manifest and pinned source
references.
