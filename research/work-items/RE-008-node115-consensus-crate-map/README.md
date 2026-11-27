# RE-008: Node #115 Complete Consensus Source Map, 5-Variant Signing Codec, and `try_propose` Guards

## Scope & Target

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `consensus` (`RE-008`)
- **Integrated Rust crate**: `src/node115-consensus` (`src/proposer.rs`, `src/wire_codec.rs`)
- **Static analysis only**: No captured binary execution; all strings, `.rela.dyn` pointers, `.data.rel.ro` `core::panic::Location` records, jump tables, and `.text` instructions are read statically.

## Direct Binary Observations

### 1. Complete 17/17 `node/src/consensus/*.rs` Inventory

Every observed `node/src/consensus/*.rs` diagnostic path in node #115 `.rodata` (17 files), all 115 `.data.rel.ro` `core::panic::Location` structs pointing to them via `R_X86_64_RELATIVE` relocations, and every `.text` FDE referencing those `Location` structs via RIP-relative `lea` are recorded in `records.json` and re-verified live by `verify.py`:

- `config.rs` (5 Locations, 1 FDE), `execution_state.rs` (11 Locations, 2 FDEs), `heartbeat_tracker.rs` (2 Locations, 2 FDEs), `latency_samplers.rs` (1 Location, 1 FDE), `liner.rs` (2 Locations, 1 FDE), `mempool.rs` (8 Locations, 5 FDEs), `network.rs` (5 Locations, 3 FDEs), `node_ips.rs` (3 Locations, 2 FDEs), `rpc.rs` (17 Locations, 8 FDEs), `server.rs` (43 Locations, 19 FDEs), `signature_tracker.rs` (1 Location, 1 FDE), `signed.rs` (1 Location, 1 FDE), `state.rs` (9 Locations, 6 FDEs), `timer.rs` (2 Locations, 4 FDEs), `types.rs` (1 Location, 1 FDE), `validator_set.rs` (2 Locations, 3 FDEs), `validator_stakes.rs` (2 Locations, 2 FDEs).

### 2. Five-Variant Consensus Signing Payload Serializer (`0x5823db0..0x58241e1`)

Both 5-entry `.rodata` jump tables (`0x935c44` serialized-size, `0x935c58` serialize-into) dispatch over variants `0..=4`, writing the 1-byte variant tag followed by bincode varint encoding via `0x58221e0` (20-byte address), `0x5822260` (32-byte hash), `0x5821f30` (varint `u32`), and `0x5822910` (varint `u64`, implemented by `node115-varint-buffer-writer`):

| Variant | Tag | Serializer FDE | Verified Field Sequence |
| --- | --- | --- | --- |
| `0` (Block) | `0x00` | `0x5967060..0x596728e` | `proposer: [u8; 20]`, `varint(tx_hashes.len())`, `N * [u8; 32]`, `time` (`0x4ecaba0`: zigzag `i64` unix secs + varint `u32` nanos), justification enum (`0 => QC` via `0x5966a30`, `1 => TC`). |
| `1` (Vote) | `0x01` | `0x5966b90..0x5966cc1` | `voter: [u8; 20]`, 5x `varint(u64)` (`+0x20, +0x28, +0x30, +0x38, +0x40`), `block_hash: [u8; 32]`. |
| `2` (Timeout) | `0x02` | `0x5967d90..0x5967e75` | `signer: [u8; 20]`, 4x `varint(u64)` (`+0x00, +0x08, +0x10, +0x18`: hardfork version/round, timeout round, high-QC round). |
| `3` (Status/Heartbeat) | `0x03` | `0x5b561e0..0x5b56317` | `sender: [u8; 20]`, `varint(u64)`, `varint(u32)`, zigzag `varint(i64)`, `varint(u64)`, payload (`0x4e05ad0`). |
| `4` (PeerMsg) | `0x04` | `0x5b5b360..0x5b5b40f` | `addr1: [u8; 20]`, `addr2: [u8; 20]`, `varint(u32)`, `varint(u64)`. |

### 3. `try_propose` Pre-Proposal Guards (`0x2e13ea0..0x2e153c9`)

Verified window `0x2e14036..0x2e140f9`:
1. Calls proposer selection through slot `0x64e86f0` (`0x595cb30`, `proposer(current_round, stake_round)`), requiring tag `0x2e`.
2. Performs 20-byte SIMD equality check (`pcmpeqb` + `pmovmskb == 0xffff`) against self address `[r13+0xbc0..0xbd4]`.
3. Enforces anti-equivocation: `cmp [r13+0xaf0], [r13+0xae0]; jae` — rejects proposing if `last_proposed_round >= current_round`.
4. Queries active stake set via slot `0x64e64b0` for `[r13+0x760]` (tag `0x2e`) and confirms self membership before constructing the block.

## Inferences & Remaining Unknowns

- **Inferences**:
  - `node115-consensus::proposer` integrates the exact `0x595cb30` weighted-event schedule model validated in `RE-008-proposer-selection-115` and exposes it through the `ProposerProvider` and `BlockProposerProvider` traits.
- **Unknowns (explicitly not claimed)**:
  - Variant 3's inner payload serializer `0x4e05ad0` and full `server.rs`/`mempool.rs`/`rpc.rs` network I/O event loops are outside this packet.
  - This packet maps all 17 source paths and closes core consensus codecs/proposer/guard logic, but does not claim whole-component byte identity or runtime parity.

## Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-consensus-crate-map/verify.py
(cd research/work-items/RE-008-node115-consensus-crate-map && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_consensus_crate_map -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/node115-consensus/Cargo.toml
```
