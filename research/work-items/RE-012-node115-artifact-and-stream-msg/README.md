# RE-012 — Node #115 `artifact`, `stream_msg`, and `abci_latency_sampler` Runtime Reconstruction

- **Target**: Linux x86-64 node `#115` (`artifacts/node/115/hl-node`), SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Component**: `node-runtime` (`RE-012`), crate `src/node-runtime` (`src/artifact.rs`, `src/stream_msg.rs`).

## Binary-Backed Findings

1. **`node/src/stream_msg.rs`** (`.rodata 0x445fdf`, `Location 0x649cee0` at `node/src/stream_msg.rs:43:48`, FDE `0x4e09ab0..0x4e09bff`, 335 B):
   - Serializes stream messages into `Vec<u8>`, panics on encode failure, and wraps the owned buffer in a 40-byte `ArcInner<Vec<u8>>` (`0x4e09b1c`, strong=1, weak=1) for zero-copy fan-out across subscriber tasks.
   - Reconstructed in `node_runtime::stream_msg::SharedStreamMsg`, paired with loopback-tested `AbciStream` greeting handshake (`serve_abci_stream_greeting` / `exchange_abci_stream_greeting`, port `3999`) and `EvmKvs` batch streaming (`serve_evm_kvs_stream` / `recv_evm_kvs_stream`, port `3998`) over `net_utils`.
2. **`node/src/artifact.rs`** (`.rodata 0x432e44`, 6 `Location` records `0x649dc08`, `0x649dc20`, `0x649dc58`, `0x649dc70`, `0x649dc88`, `0x649dcb0`; FDEs `0x4ec71b0..0x4ec79f7` [2,119 B] and `0x4e4cbb0..0x4e4d69b` [2,795 B]):
   - Artifact directory `"node-artifact-2"` (`0x9188e2`), updater task labels `"node artifact updater"` (`0x9188b9`) and `"update_node_artifact"` (`0x9188ce`), metadata filenames `"node_metadata.json"` (`0x468a6a`) and `"visor_metadata.json"` (`0x468a7c`).
   - Poll interval `f64 = 5.0` seconds at `.rodata 0x4593d0`.
   - `IndexedArtifactSerde` (2-element struct, `0x465923` / `0x46834d`) wrapping `IndexedArtifactContentSerde` (`0x465a39`) with 5 observed content variants (`NodeMetadata`, `VisorMetadata`, `HotfixMetadata`, `NodeArtifact`, `PublisherBinaryMetadata` at `0x46593e..0x465988`), `<dir>/<index>.json` format fragments (`0x439f04`), and strict monotonic index enforcement (`"download index did not increase"` at `0x434625`).
   - Reconstructed in `node_runtime::artifact::{IndexedArtifact, IndexedArtifactContent, ArtifactUpdater}`.
3. **`node/src/abci_latency_sampler.rs`** (`.rodata 0x44bf3e`, 3 `Location` records `0x64a3618` L70:38, `0x64a3630` L73:48, `0x64a3648` L60:41):
   - Reconstructed as bounded ring sampler `node_runtime::stream_msg::AbciLatencySampler`.

## Verification

- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_artifact_and_stream_msg_115.py`
- `cargo test --offline --locked --manifest-path src/node-runtime/Cargo.toml` (debug and `--release`)
- `cargo clippy --offline --locked --all-targets --manifest-path src/node-runtime/Cargo.toml -- -D warnings`
- `(cd research/work-items/RE-012-node115-artifact-and-stream-msg && sha256sum -c MANIFEST.sha256)`
