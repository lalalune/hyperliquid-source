# RE-012 — Node #115 Gossip RPC Wire Parity, `connections`, and `local_abci_state`

- **Target**: Linux x86-64 node `#115` (`artifacts/node/115/hl-node`), SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Components**: `transport` (`src/net-utils`) and `node-runtime` (`src/node-runtime`).

## Binary-Backed Findings

1. **`GossipRpcRequest` (`0x5aac6a0..0x5aac7b7`, 279 B)** and **`GossipRpcResponse` (`0x5aac7c0..0x5aacc22`, 1,122 B; `0x2e466b0..0x2e469a9`, 761 B)**:
   - Exact `#115` outer `GossipRpcResponse` tag assignment:
     - `0` = `ClientBlocks(Result<Vec<ClientBlock>, ClientBlocksError>)`
     - `1` = `Peers(Vec<PeerEntry>)` (limit `10_000` = `0x2710` at `0x2b6a7df`)
     - `2` = `GossipStatus(Option<GossipStatus>)`
2. **`ClientBlocksError` (`0x5a2d540..0x5a2d788` Debug JT `0x938ee8`; Decode JT `0x939f28`)**:
   - Exact 7 wire variants `0..=6`: `0=PeerOnlyRequest`, `1=InvalidRange { start_round, end_round }`, `2=RangeTooLarge`, `3=RateLimited`, `4=NoClientBlocks`, `5=RoundTooSmall { start_round, first_parent_round }`, `6=RoundTooLarge { end_round, max_round }`.
3. **`GossipStatus` (`0x5aabd20..0x5aabf7a`, 602 B; Debug `0x2c7c740..0x2c7c7dc` & `0x5a2e380..0x5a2e41c`, 156 B)**:
   - Exact 4 struct fields encoded in wire order: `hardfork_height: u64`, `latest_height: u64`, `hardfork: Hardfork { version: u64, round: u64 }`, `latest_consensus_round: Option<u64>`.
4. **`Peers` record (`0x5aaa460..0x5aaa628`, 456 B; set normalizer `0x4de6210..0x4de6467`)**:
   - Exact wire layout: `NodeIp` enum tag `0` (`u32`), 4 raw IPv4 octets, `is_validator: bool`, `value: u64` varint (`0x5821340`).
5. **`node/src/connections.rs` (`0x2accee0..0x2ad0db0`, 16,080 B; `0x2ad0db0..0x2ad4db7`, 16,391 B)**:
   - `"connection_checks"` timeout `f64 = 5.0` (`0x4593d0` loaded at `0x2acd08c`); `"handle_node_connection"` outer timeout `f64 = 10_000_000_000.0` (`0x4594a0` loaded at `0x2ace646`).
   - Exact rejection diagnostics (`0x6055b4..0x605781`): timeout, no quorum yet, unreadable greeting, peer verification failure, duplicate connected peer, max connection age reached.
6. **`node/src/local_abci_state.rs` (`0x2adce40..0x2ae00f8`, 12,984 B)**:
   - Requires `>= 2` valid RPC statuses (`"unable to find at least 2 valid rpc statuses"` at `0x605a53`).
   - Exact height lag check at `0x2add488..0x2add4ad`: `local_height.saturating_add(20_000) <= remote_latest_height` (`0x4e20`) -> `"local height is too far behind"` (`0x6059b5`).
   - Exact hardfork check at `0x2add4bf..0x2add4ef`: `local_height < remote_hardfork_height || local_hardfork < remote_hardfork` -> `"local height is from stale hardfork"` (`0x605992`).
   - Exact frozen upgrade round window at `0x2add52c..0x2add54e`: `local_hardfork.round.saturating_add(400)` (`0x190`) vs `remote_latest_consensus_round`.
