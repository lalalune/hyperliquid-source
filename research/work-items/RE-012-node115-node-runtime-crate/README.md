# RE-012: Node #115 `node-runtime` CLI, startup, NodePort, gossip config & sync

Component: `node-runtime`. Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`),
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Binary Observations

1. **All 21 non-consensus `node/src/*.rs` diagnostic source paths anchored to `.rodata` and `.data.rel.ro` `core::panic::Location` records**:
   - `abci_latency_sampler.rs` (`0x44bf3e`), `abci_stream.rs` (`0x449e04`), `artifact.rs` (`0x432e44`), `aux.rs` (`0x4482a4`), `channel.rs` (`0x430aa0`), `connections.rs` (`0x445db6`), `evm_kvs.rs` (`0x4432b3`), `firewall_ips.rs` (`0x43f53e`), `gossip_config.rs` (`0x449029`), `gossip_rpc.rs` (`0x44af16`), `gossip_rpc_client.rs` (`0x436a05`), `group_and_seq_sampler.rs` (`0x431e32`), `hl_node.rs` (`0x436a23`), `local_abci_state.rs` (`0x44ac48`), `node.rs` (`0x44aca3`), `node_port.rs` (`0x44bba7`), `nv_stream.rs` (`0x43bce4`), `startup.rs` (`0x438c81`), `stream_msg.rs` (`0x445fdf`), `utils.rs` (`0x439d32`), `visor_time_lock.rs` (`0x43bec9`).

2. **Exact 7-variant `NodePort` jump table (`0x9394e8`, `0x5a5e5c0` in FDE `0x5a5e290..0x5a60a43`)**:
   - Variant `0` (`0x5a5e5d0`): `4001` (`0x0fa1`)
   - Variant `1` (`0x5a5e3eb`): `4002` (`0x0fa2`, `gossip_rpc`)
   - Variant `2` (`0x5a5e8a9`): `4003` (`0x0fa3`)
   - Variant `3` (`0x5a5e8b2`): `4004` (`0x0fa4`)
   - Variant `4` (`0x5a5e8a0`): `4005` (`0x0fa5`)
   - Variant `5` (`0x5a5e8bb`): `3998` (`0x0f9e`, uncompressed local)
   - Variant `6` (`0x5a5e8c4`): `3999` (`0x0f9f`, uncompressed local)

3. **`GossipConfigInner`, `hl-node` CLI, Build Stamp, and Firewall/Visor Constants (`.rodata 0x92a770..0x92ade0`, `0x605d88`, `0x93ad97`)**:
   - Build stamp (`0x92a8d9`): `28076c144c66d3f34ca321ac85ca19f461ade137|2026-10-25 16:48:13 +0800|uncommitted=false`
   - `GossipConfigInner` (`0x90f9aa`): `root_node_ips` (asserted non-empty at `0x92a75d`), `try_new_peers`, `chain`, `reserved_peer_ips`, `n_gossip_peers`, `split_client_blocks`, `slow_abci_engine_read_increment`; override file `override_gossip_config.json` (`0x92a85b`).
   - 9 CLI subcommands (`0x92aca7..0x92adc5`): `run-non-validator`, `translate-abci-state`, `send-signed-action`, `check-reachability`, `compute-referrer-states`, `compute-l4-snapshots`, `change-validator-profile`, `approve-non-expiring-agent`, `serve-eth-rpc`.
   - Chains (`0x92ab52`): `Local`, `Sandbox`, `Testnet`, `Mainnet`.
   - Firewall diff labels (`0x439ec6`): `abci_minus_firewall`, `firewall_minus_abci`; reachability check message (`0x605d88`); visor paths (`0x93ad97`): `visor_time_lock`, `publisher_visor_time_lock`, `visor_staging_NOT_READY`.

## Implementation & Limits

Independently authored `#![forbid(unsafe_code)]` MIT crate in `src/node-runtime/` joining `bincode-fork`, `net-utils`, and 7 verified node #115 runtime micro-crates (`cli-validators`, `startup-output`, `startup-admission`, `startup-path-join`, `startup-sorted-admission`, `restart-delay`, `restart-threshold`), exposing `BlockSink` and `ConsensusHook` seams for `storage-abci` and `consensus-staking` integration.
Live validator networking, compiled `.text` identity, and Tokio async orchestration are out of scope for this packet.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_node_runtime_115.py
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/net-runtime \
  cargo test --offline --locked --manifest-path src/node-runtime/Cargo.toml
```
