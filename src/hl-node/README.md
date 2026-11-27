# `hl-node` Unified Workspace & Binary Skeleton (Node #115)

Independently authored, `#![forbid(unsafe_code)]`, zero-external-dependency Cargo workspace and runnable `hl-node` CLI binary unifying the reconstructed node #115 first-party library crates:

- **Foundation (`base`)**: `node115-base` (linking 39 verified foundation micro-crates)
- **Global constants (`global_constants`)**: `global-constants`
- **Serialization (`bincode_fork`)**: `bincode-fork`
- **Storage (`db`)**: `node115-db`
- **Transport (`net_utils`)**: `net-utils`
- **Node runtime (`node`)**: `node-runtime`
- **Consensus (`node/consensus`)**: `node115-consensus`
- **Staking (`l1/staking`, `l1/c_staking`)**: `node115-staking`
- **Block execution (`l1/abci`)**: `node115-abci`, `node115-abci-checkpoint-replay-fixture`
- **Assets & quantities (`l1/asset`, `l1/qtys`)**: `node115-assets`
- **Fees & volume (`l1/fees`)**: `node115-fees`
- **Order books (`l1/book`, `l1/slab`)**: `node115-orderbook`
- **Action wire & dispatch (`l1/action`, `l1/exchange/handlers`)**: `action-wire`, `action-dispatch`
- **Clearinghouse & risk (`l1/clearinghouse`)**: `clearinghouse`
- **Exchange orchestration (`l1/exchange`)**: `exchange`
- **Vaults (`l1/vault`, `l1/sub_account`)**: `vaults`
- **DEX registry (`l1/dex_registry`)**: `dex-registry`
- **L1 shared (`l1/*`)**: `l1-shared`
- **Bridge (`l1/bridge2`, `l1/bridge_request`)**: `bridge`
- **HyperEVM (`l1/evm`)**: `evm`
- **EVM JSON-RPC (`evm_rpc`)**: `evm-rpc`
- **Info API (`info_server`)**: `info-api`
- **CLI / Startup**: `node115-cli-validators`, `node115-startup-output`

Target: Linux x86-64 node #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Release profile sets `overflow-checks = true` per `RE-002-node115-private-forks-provenance`.

## End-to-End Local Runtime Pipelines (`src/hl-node/src/{engine,http_server,peer_loopback}.rs`)

- **Checkpoint Restore, Block Replay & BLAKE3 ABCI State Root (`engine.rs`)**: Persists LZ4 + `bincode-fork` checkpoints (`checkpoint/<height>/checkpoint.bin`) and companion `lt_hashes.json` under `node115_db::db_home::DbHome`, computes exact node #115 BLAKE3 reduction-tree roots via `node115-abci` + `node115-abci-blake3`, implements `node_runtime::peer_sync::BlockSink`, and fails closed on corrupted `lt_hashes.json` or mismatched state roots across restart.
- **Localhost HTTP `/health`, `/info` & `/evm` Server (`http_server.rs`)**: Pure-std `std::net::TcpListener` HTTP/1.1 server dispatching `POST /info` through `info-api` (55 verified `#115` variants + localhost gate) and `POST /evm` through `evm-rpc` (`MethodRouter` 29 methods + `ExpensiveCallLimiter`) over real loopback sockets across restarts.
- **Loopback TCP Peer Sync (`peer_loopback.rs`)**: Synchronizes `GossipRpc` (`Peers`, `Status`, `ClientBlocks`), `AbciStream` greeting handshake, and `EvmKvs` batches over real `127.0.0.1` TCP sockets (`node-runtime` + `net-utils` + `bincode-fork`), converging follower and seed engines to byte-identical 32-byte BLAKE3 ABCI state roots.

## Docker delivery (`src/hl-node/Dockerfile`)

`src/hl-node/Dockerfile` defines a pinned multi-stage Linux/amd64 source build (`rust:1.95.0-bookworm` builder compiling `hl-node` with `cargo build --offline --locked --release`, copied into `ubuntu:24.04` running as unprivileged `hluser` UID/GID `10000` with persistent `/home/hluser/hl/data` volume and `HEALTHCHECK`).

**Verification boundary**: Host native `cargo test --offline --locked --release` (including localhost HTTP `/info` + `/evm`, loopback TCP peer sync, and checkpoint restart persistence) and binary execution were verified directly on Linux x86-64; container build/run via `docker build` was not executed in this environment because `/var/run/docker.sock` returned `permission denied` (no container build/run success is claimed without an actual run).

## Limitations

- This unified binary links all 23/23 reconstructed components (all 8 real first-party crates: `base`, `db`, `net_utils`, `node`, `l1`, `global_constants`, `info_server`, `evm_rpc`) and verifies offline/loopback block replay, BLAKE3 state-root checkpoint restart, localhost `/info` + `/evm` HTTP serving, and loopback TCP peer sync.
- Public internet P2P gossip, live Mainnet/Testnet chain sync, and live validator signing remain disabled; no full-node network acceptance or binary-equivalence claim is made.
