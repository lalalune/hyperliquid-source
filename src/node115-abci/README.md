# `node115-abci`

Integrated node #115 ABCI block-execution and state-checkpoint library unifying all 4 observed `l1/src/abci/*.rs` modules (`abci_hash`, `hash_signature_tracker`, `state`, `engine`) and linking `node115-db`, `node115-abci-checkpoint-replay-fixture`, `node115-digest-reference-handoff`, `node115-quorum-line`, `node115-digest-support-gate`, and `node115-digest-vote-admission`.

- Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- `#![forbid(unsafe_code)]`, zero external crates.io dependencies.
- Evidence packets: `research/work-items/RE-009-node115-abci-crate-map/`, `research/work-items/RE-009-node115-expected-root-provenance/`, `research/work-items/RE-009-node115-checkpoint-replay-root-fixture/`.
