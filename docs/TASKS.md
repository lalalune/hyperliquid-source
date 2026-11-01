# Ready work queue

All work is initially unclaimed. Record a claim in a GitHub issue or your PR
before overlapping changes; there is no automatic ownership allocator. Each
row is a bounded starting task, not a claim that its subsystem is recovered.

The delivery target is the [source-built network node](SCOPE.md#source-built-network-node).
Prioritize the existing RE-001/002/005/012 work that establishes startup, build
closure and peer protocol, followed by RE-009/008 state synchronization and
validation. A container around a captured proprietary executable does not meet
that target. Keep #94 baseline recovery separate from current-network drift.

| ID | Priority | Scope | First evidence | Deliverable / acceptance | Depends on |
| --- | --- | --- | --- | --- | --- |
| RE-001 | P0 | #94 function map | `make index`; catalogue comment seeds | Decode FDE ranges, account for duplicates/missing functions, validate initial entrypoints and xrefs with digest-bound records | None |
| RE-002 | P0 | Build provenance | Inventories, `.comment`, source/dependency paths | Document exact vs inferred compiler flags, crate graph and fork versions; deterministic Linux build plan with unresolved fields | None |
| RE-003 | P0 | Test harness design | SCOPE.md and evidence template | Isolated offline differential protocol, no-network/side-effect controls, fixture identities, positive and negative controls; obtain execution approval before running target | None |
| RE-004 | P1 | Quantities/rounding | `l1/qtys/*`, `l1/asset/pdi.rs` reference leads | Validate one bounded arithmetic family, widths, rounding and overflow; independently authored Rust + target-grounded tests | RE-001, RE-002; RE-003 for execution |
| RE-005 | P1 | Serialization/signing | `bincode_fork/*`, `l1/action/rmp_signable.rs` | Wire-layout record, discriminant/length/error cases and minimal codec; no production keys | RE-001; RE-003 for execution |
| RE-006 | P1 | Book transitions | `l1/book/*`, `l1/slab/*`, `l1/books.rs` | One validated insert/cancel/match call path with state/layout evidence and boundary fixtures | RE-001, RE-004 |
| RE-007 | P1 | Risk/oracles/liquidation | `l1/clearinghouse/*` | Explicit price/size/wei units, one margin or liquidation path, all called helpers and unknown branches | RE-001, RE-004 |
| RE-008 | P1 | Consensus wire/state | `node/consensus/types.rs`, `signed.rs`, `state.rs` | Validated message/tag/signature map, quorum math and one transition; no live network | RE-001, RE-005 |
| RE-009 | P1 | Storage/state roots | `db/*`, `l1/abci/state.rs` | Small fixture schema, serialization/hash ownership and snapshot compatibility evidence | RE-001, RE-005 |
| RE-010 | P2 | Exchange handlers | `l1/exchange/impl_execute_action.rs`, handler splits | Map dispatch tags to #94 real boundaries; distinguish agent splits from original functions | RE-001, RE-005 |
| RE-011 | P2 | EVM/forks | `l1/evm/*`, `evm_rpc/*`, `upstream/hyper-evm-sync` | Dependency/fork matrix and one bounded EVM adapter or RPC path; no full-chain downloads | RE-002, RE-009 |
| RE-012 | P2 | APIs/gossip/startup | `info_server/*`, `net_utils/*`, `node/hl_node.rs` | One request/frame/CLI path mapped to binary; identify writes and external side effects | RE-001, RE-005 |
| RE-013 | P2 | Visor | Captured visor, imported disassembly | Separate compiler/index inventory and static download/verify/spawn control flow | None |
| RE-014 | P2 | Release drift | #94/#115 inventories and catalogue path lists | Target-bound cross-version mapping; qualify changed code separately from missing diagnostic paths | RE-001 |
| RE-015 | P2 | `global_constants/*` | `/static_config` `0x1ef5f7`, `/cham` `0x1fc0ee`, `NvTestnet` `0x2180ff` | Digest-bound literal inventory, pool-entry xrefs, 76-entry discriminant table and reference comparison; no gate | RE-001 |

The component map also names vaults, bridge, staking, fees, DEX registry and
remaining shared state. Each accepts a bounded packet under the same process;
these areas are not omitted simply because the first queue favors dependency
leaves. Do not combine independent component claims into one completion number.
