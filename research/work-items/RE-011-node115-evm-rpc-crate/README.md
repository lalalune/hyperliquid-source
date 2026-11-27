# RE-011: node #115 `evm_rpc` 6-source-file map, 29-method registry, and `evm-rpc` crate integration

This packet maps all six observed `evm_rpc/src/*.rs` diagnostic source paths (`evm_rpc.rs`, `evm_store.rs`, `evm_write_forwarder.rs`, `expensive_call_limiter.rs`, `method_router.rs`, `reth_rpc_helpers_copied.rs`), binds all 57 `R_X86_64_RELATIVE` panic `Location` records, extracts all 29 registered JSON-RPC method names (`0x2a05f60`, `0x2e375a0`, `0x17512f3`), and integrates `node115-storage-key-builder` and `node115-block-number-text` with `evm` and `global-constants` into `src/evm-rpc/`.

- Component ID: `evm-rpc` (`evm_rpc/*`); task `RE-011`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Claim status:
  - **Observation**: ELF section bounds, all 6 `evm_rpc/src/*.rs` `.rodata` paths, all 57 panic `Location` records (`va`, `file`, `line`, `col`), all 26 core methods registered in `0x2a05f60` + `net_version`/`web3_clientVersion` in `0x2e375a0` + `eth_sendRawTransaction` in `0x17512f3`, forwarding URLs (`https://rpc.hyperliquid-testnet.xyz/evm`, `https://rpc.hyperliquid.xyz/evm`), `"Method not found"` (`0x453cf0`), and FDE body SHA-256 digests.
  - **Inference**: Rust module organization (`method_router`, `limiter`, `forwarder`, `fee_history`, `store`) and synchronous trait/API signatures.
  - **Unresolved**: Full Tokio async HTTP/jsonrpsee transport loop, RocksDB live iterator vtables, full `eth_call` / `eth_estimateGas` execution against live EVM state, and whole-crate `rustc 1.95.0` codegen identity.
- Captured code executed: `false`. Static binary analysis + independently authored MIT Rust tests only.
- Progress gate: no automatic gate flip claimed in this packet.

## Key node #115 observations

1. **All 6 `evm_rpc/src/*.rs` files & 57 panic `Location` records**:
   - `evm_rpc/src/evm_rpc.rs` (19), `evm_rpc/src/evm_store.rs` (20), `evm_rpc/src/method_router.rs` (9), `evm_rpc/src/expensive_call_limiter.rs` (5), `evm_rpc/src/evm_write_forwarder.rs` (2), `evm_rpc/src/reth_rpc_helpers_copied.rs` (2).
2. **All 29 registered EVM JSON-RPC methods**:
   - 26 core methods in `0x2a05f60` (incl. HyperEVM custom RPCs `eth_bigBlockGasPrice`, `eth_getSystemTxsByBlockHash`, `eth_getSystemTxsByBlockNumber`, `eth_usingBigBlocks`), plus `net_version`, `web3_clientVersion`, and `eth_sendRawTransaction`.
3. **Integrated `src/evm-rpc/` crate**: joins `node115-storage-key-builder`, `node115-block-number-text`, `evm`, and `global-constants` (`#![forbid(unsafe_code)]`, 0 external crates.io deps).

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/evm-bridge-api \
  cargo test --offline --locked --manifest-path src/evm-rpc/Cargo.toml
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_evm_rpc_crate_115 -v
```
