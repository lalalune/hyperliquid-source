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
- **CLI / Startup**: `node115-cli-validators`, `node115-startup-output`

Target: Linux x86-64 node #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Release profile sets `overflow-checks = true` per `RE-002-node115-private-forks-provenance`.

## Docker delivery (`src/hl-node/Dockerfile`)

`src/hl-node/Dockerfile` defines a pinned multi-stage Linux/amd64 source build (`rust:1.95.0-bookworm` builder compiling `hl-node` with `cargo build --offline --locked --release`, copied into `ubuntu:24.04` running as unprivileged `hluser` UID/GID `10000` with persistent `/home/hluser/hl/data` volume and `HEALTHCHECK`).

**Verification boundary**: Host native `cargo test --offline --locked --release` and binary execution were verified directly on Linux x86-64; container build/run via `docker build` was not executed in this environment because `/var/run/docker.sock` returned `permission denied` (no container build/run success is claimed without an actual run).

## Limitations

- This unified binary validates CLI arguments and exercises offline cross-crate subsystem wiring only.
- Live P2P networking, validator signing, live chain sync, HyperEVM execution, Info HTTP server, and EVM JSON-RPC server integration remain in progress across sibling streams and are wired in as those integrated crates land.
- No full-node acceptance or binary-equivalence claim is made.
