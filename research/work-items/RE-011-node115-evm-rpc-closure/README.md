# RE-011: Node #115 `evm-rpc` Full-Scope Closure (`evm_rpc/src/*.rs`)

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `evm-rpc` (`evm_rpc/*`).
- **Closure Status**: Full static inventory & behavioral closure ready for joint `mapped`/`built`/`behavior` gate review (`identity` remains `false`).

## Complete Inventory Authenticated Directly Against Node #115

- **Source files**: **6/6** `evm_rpc/src/*.rs` files (exact match with `research/imported/hl-node-115.inventory.json`).
- **Panic `Location` structs**: **57/57** `.data.rel.ro` entries (0 unreferenced).
- **Referencing `.text` FDEs**: **48/48** exact FDEs totaling **145,280 B** verified against `work/index/node-115-fde.tsv`.
- **Registered JSON-RPC methods**: **29/29** (`26` core in `0x2a05f60` + `2` extra `net_version`/`web3_clientVersion` in `0x2e375a0` + `1` write-forwarder `eth_sendRawTransaction` in `0x17512f3`).
- **Compiled-byte identity already landed for `evm-rpc`**:
  - Wave 3 (`RE-015-node115-stream-f-byte-matches`) + Slice 11 (`RE-011-node115-stream-f-logic-byte-matches`: `EthCallOverrides::FieldVisitor::visit_str` `0x29aee50` 264 B, `AccountOverride::FieldVisitor::visit_str` `0x2745310` 354 B with Hyperliquid's `MovePrecompileToAddress`).

## 1-to-1 Source File Mapping

| Node #115 Source File | Locations | Implementation Paths |
| --- | ---: | --- |
| `evm_rpc/src/evm_rpc.rs` | 19 | `src/evm-rpc/src/{fee_history,limiter,method_router}.rs`, `src/node115-block-number-text/src/lib.rs`, `src/node115-fee-history-reward/lib.rs` |
| `evm_rpc/src/evm_store.rs` | 20 | `src/evm-rpc/src/store.rs`, `src/node115-storage-key-builder/lib.rs` |
| `evm_rpc/src/evm_write_forwarder.rs` | 2 | `src/evm-rpc/src/forwarder.rs` |
| `evm_rpc/src/expensive_call_limiter.rs` | 5 | `src/evm-rpc/src/limiter.rs` |
| `evm_rpc/src/method_router.rs` | 9 | `src/evm-rpc/src/{method_router,lib}.rs` |
| `evm_rpc/src/reth_rpc_helpers_copied.rs` | 2 | `src/evm-rpc/src/fee_history.rs`, `src/node115-fee-history-reward/lib.rs` |

## Verification

```bash
(cd research/work-items/RE-011-node115-evm-rpc-closure && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-011-node115-evm-rpc-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_evm_rpc_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/evm-rpc/Cargo.toml
```
