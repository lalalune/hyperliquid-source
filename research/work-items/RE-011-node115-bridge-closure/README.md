# RE-011: Node #115 `bridge` Full-Scope Closure (`l1/src/bridge2.rs`, `l1/src/bridge_request.rs`)

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `bridge` (`l1/bridge2.rs`, `l1/bridge_request.rs`).
- **Closure Status**: Full static inventory and behavioral closure ready for strict `docs/SCOPE.md` joint `mapped`/`built`/`behavior` gate review (`identity` remains `false`).

## Complete Inventory Authenticated Directly Against Node #115

- **Source files**: **2/2** (`l1/src/bridge2.rs`, `l1/src/bridge_request.rs`, exact match with `research/imported/hl-node-115.inventory.json`).
- **Panic `Location` structs**: **7/7** `.data.rel.ro` entries (`6` in `l1/src/bridge2.rs`, `1` in `l1/src/bridge_request.rs`, **0 unreferenced**).
- **FDE coverage**: **6/6** Location-referencing `.text` FDEs (`8,366 B`) + **25/25** disjoint companion business/serde FDEs (`29,054 B`: `0x154d390` Arbitrum contract registry `5,594 B`, `0x4526230` 8-variant `BridgeRequest` ABI dispatcher `3,088 B`, `0x457cf20` `BridgeRole` formatter `50 B`, all 6 ABI tag encoders, 3 `Bridge2` 15-field state serializers, and all 13 live-compiled `Bridge2`/`EthEventId` serde FDEs from `RE-011-node115-stream-f-logic-byte-matches`) = **31 unique FDEs (`37,420 B`)** verified against `work/index/node-115-fde.tsv`.
- **Binary anchors verified**:
  - **7 `.text` instruction anchors**: `0x44d8448` (`cmpw $0x1a2`), `0x44d8454` (`Bridge2::bal` checked sub underflow guard), `0x44d7d4b` (`imul $0x68` deposit ring stride), `0x4526247` (jump table `0x7d3708` `lea`), `0x452704b` (`Mainnet` tag 3 + `"a"` source byte), `0x4527052` (`0xa4b1` = 42161 / `0x66eee` = 421614 Arbitrum chain IDs), `0x4526eda` (contract chain selector).
  - **16 `.rodata` string literals**: all 4 canonical Arbitrum contracts (`Usdc2Mainnet`, `Bridge2Mainnet`, `Bridge2Testnet`, `Usdc2Testnet`) + `/contract_addresses/` fallback + `"bridge2 withdrawal balance bug"` + 6 `BridgeRequest` ABI labels.
  - **15/15 `Bridge2` schema fields** in `.rodata`.
- **Honest compiled-byte identity status**: `identity_gate_satisfied: false`. Landed first-party compiled-byte windows for `bridge` remain tracked separately in `research/byte-windows.json` (`64` windows / `19,184 B`) and `research/work-items/RE-011-node115-stream-f-logic-byte-matches` (`13` disjoint FDEs / `11,526 B`).

## 1-to-1 Source File Mapping (All 6 Registered `bridge` Crates)

| Node #115 Source File | Locations | Implementation Paths |
| --- | ---: | --- |
| `l1/src/bridge2.rs` | 6 | `src/bridge/src/{contracts,eth_event,state}.rs`, `src/node115-bridge-event-name-decoder/src/lib.rs`, `src/node115-bridge-request-mutation/lib.rs` |
| `l1/src/bridge_request.rs` | 1 | `src/bridge/src/{request,lib}.rs`, `src/node115-bridge-preimage/lib.rs`, `src/node115-bridge-request-abi/src/lib.rs`, `src/node115-bridge-word-flatten/src/lib.rs` |

## Verification

```bash
(cd research/work-items/RE-011-node115-bridge-closure && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-011-node115-bridge-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bridge_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/bridge/Cargo.toml
```
