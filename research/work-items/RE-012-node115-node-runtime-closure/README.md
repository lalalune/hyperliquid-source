# RE-012: Node #115 `node-runtime` (Non-Consensus `node/src/*.rs`) Complete 21-File / 342-Location / 99-FDE Full-Scope Closure

- **Component ID**: `node-runtime` (`node` crate: all 21 observed non-consensus `node/src/*.rs` files; `node/src/consensus/*` is owned by `consensus-staking`).
- **Workspace crate**: `src/node-runtime` (`#![forbid(unsafe_code)]`, pure `std` + `net-utils` + `bincode-fork` + verified Stream C node #115 micro-crates, zero external crates.io dependencies; integrated into `src/hl-node`).
- **Target release**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Static verification only**: Captured binary is never executed.

## Complete Non-Consensus `node/src/*.rs` Inventory (21/21 Files, 342/342 Locations, 99/99 FDEs = 511,574 B)

Every `.data.rel.ro` `core::panic::Location` struct whose path begins with `node/src/` outside `node/src/consensus/` (all 342/342, 0 unreferenced) and every `.text` FDE referencing any of those 342 `Location`s (all 99/99) is authenticated in `records.json`:

1. **`node/src/hl_node.rs` (81 Locations, 18 FDEs)** & **`node/src/startup.rs` (39 Locations, 10 FDEs)** -> `src/node-runtime/src/cli.rs` + `src/node-runtime/src/restart.rs`:
   - CLI parsing (`Chain`, `CliArgs`, `Command`), node #115 validator guards (`node115-cli-validators`), replica output settings (`node115-startup-output`), and startup directory admission (`node115-startup-admission`, `node115-startup-path-join`, `node115-startup-sorted-admission`).
2. **`node/src/node_port.rs` (6 Locations, 5 FDEs)** -> `src/node-runtime/src/node_port.rs`:
   - All 7 `NodePort` discriminants verified directly from jump table `0x9394e8` (`0x5a5e5c0`) and `movw` instructions: `Gossip=4001` (`0x5a5e5d0`), `GossipRpc=4002` (`0x5a5e3eb`), `Consensus=4003` (`0x5a5e8a9`), `NvStream=4004` (`0x5a5e8b2`), `ConsensusAux=4005` (`0x5a5e8a0`), `EvmKvs=3998` (`0x5a5e8bb`), `AbciStream=3999` (`0x5a5e8c4`), plus `"NodePort::listen"` (`0x456b70`).
3. **`node/src/gossip_config.rs` (31 Locations, 10 FDEs)** -> `src/node-runtime/src/gossip_config.rs`:
   - `GossipConfigInner` (`0x90f9aa`, `Debug::fmt` `0x5656a20..0x5656bee`), `override_gossip_config.json` (`0x92a85b`), `!res.read().root_node_ips.is_empty()` (`0x92a75d`), and signed-dword metadata hot-reload gate (`node115-gossip-reload`).
4. **`node/src/gossip_rpc.rs` (7 Locations, 4 FDEs)**, **`node/src/gossip_rpc_client.rs` (13 Locations, 8 FDEs)**, **`node/src/nv_stream.rs` (27 Locations, 7 FDEs)**, **`node/src/node.rs` (57 Locations, 19 FDEs)** -> `src/node-runtime/src/peer_sync.rs` + `src/node-runtime/src/restart.rs`:
   - `GossipRpcRequest` (`0x5aac6a0`), `GossipRpcResponse` (`0x5a2e730`), 7-variant `ClientBlocksError` (`0x5a2d540`, `.rodata` `0x93c19f..0x93c1f1`), `GossipStatus` (`0x5aabd20`), `PeerEntry` (`0x5aaa460`), loopback peer discovery / block sync with `BlockSink`/`ConsensusHook` seams, and exponential restart backoff (`node115-restart-delay`, `node115-restart-threshold`).
5. **`node/src/connections.rs` (17 Locations, 9 FDEs)** -> `src/node-runtime/src/connections.rs`:
   - Active connection registry enforcing node #115 connection-check timeouts and max-age eviction.
6. **`node/src/local_abci_state.rs` (8 Locations, 2 FDEs)** -> `src/node-runtime/src/local_abci_state.rs`:
   - Local ABCI state bootstrap decision ladder (`applying hardfork` `0x60592f`, lag bounds, min RPC statuses, upgrade round window).
7. **`node/src/artifact.rs` (6 Locations, 2 FDEs)** & **`node/src/visor_time_lock.rs` (17 Locations, 4 FDEs)** -> `src/node-runtime/src/artifact.rs` + `src/node-runtime/src/firewall.rs`:
   - Strictly increasing indexed artifact updater (`node_metadata.json` `0x468a6a`, `visor_metadata.json` `0x468a7c`, `"index did not increase"` `0x4305c9`, `"visor_time_lock"` `0x435d7c`).
8. **`node/src/firewall_ips.rs` (1 Location, 1 FDE)** -> `src/node-runtime/src/firewall.rs`:
   - Firewall IP allowlist diffing and peer reachability check.
9. **`node/src/abci_stream.rs` (2 Locations, 2 FDEs)**, **`node/src/evm_kvs.rs` (19 Locations, 6 FDEs)**, **`node/src/stream_msg.rs` (1 Location, 1 FDE)**, **`node/src/abci_latency_sampler.rs` (3 Locations, 3 FDEs)** -> `src/node-runtime/src/stream_msg.rs`:
   - Port `3999` `AbciStream` greeting exchange, port `3998` `EvmKvs` streaming, `SharedStreamMsg`, and `AbciLatencySampler`.
10. **`node/src/aux.rs` (1 Location, 1 FDE)**, **`node/src/channel.rs` (3 Locations, 3 FDEs)**, **`node/src/group_and_seq_sampler.rs` (1 Location, 2 FDEs)**, **`node/src/utils.rs` (2 Locations, 1 FDE)** -> `src/node-runtime/src/aux.rs`:
    - Aux output stream config, priority channel, group/seq sampler, and nested-runtime `block_on_sync` guard.

## Compiled-Byte Identity Accounting (`node-runtime`)

- `RE-012-node115-stream-c-byte-matches`: includes verified `node-runtime` windows (`GossipStatus::fmt` `0x2c7c740` / `0x5a2e380`, `0x5a2e340`, and `node` `visit_str`/field visitors), plus standalone Stream C micro-crates (`node115-restart-*`, `node115-startup-*`, `node115-cli-validators`, `node115-gossip-*`, etc.).
- `identity` gate remains strictly `false` until full-crate non-consensus `node` FDE compiled-byte identity is proved.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-012-node115-node-runtime-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node_runtime_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/node-runtime/Cargo.toml
```
