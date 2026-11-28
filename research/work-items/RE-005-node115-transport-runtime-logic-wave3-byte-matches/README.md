# RE-005: Node #115 First-Party `node-runtime` Gossip Protocol Wave 3 Compiled-Byte FDE Matches (`3,893 B`)

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler**: `rustc +1.95.0` (`--edition=2021`, `-C opt-level=3`, `-C overflow-checks=yes`, `#![forbid(unsafe_code)]`)
  - `std_bincode/`: zero external crates.io dependencies (`-C relocation-model=pie -C lto=off -C codegen-units=1 --emit=obj`) — **7 FDEs = `3,003 B`** (`2,644/3,003 = 88.05%` raw-equal)
  - `jem_serde/`: offline locked Cargo ThinLTO + `tikv-jemallocator = "=0.6.0"` + `serde = "=1.0.229"` + `serde_json = "=1.0.140"` (`licenses.json` permissive SPDX audited) — **1 FDE = `890 B`** (`794/890 = 89.21%` raw-equal)
- **Source kind**: `first-party clean-room rebuild` (zero `core::`/`alloc::`/`std::` or third-party dependency attribution)
- **Matched coverage**: **8 strictly disjoint exact `.eh_frame` FDEs = `3,893 B`** (`3,438 / 3,893 = 88.31%` raw-equal bytes; 100.00% strict `tools/byte_progress.py::compare` relocation-qualified identity, 0 non-relocation byte differences, 0 overlaps against `research/byte-windows.json` and all sibling packets)
  - **`node-runtime`**: **8 FDEs = `3,893 B`** (`node/src/gossip_rpc.rs` wire protocol encoders & serializer)

## Verified FDE Windows (`8/8` strict relocation-qualified matches)

| Node #115 FDE VA | Size (B) | Raw-Equal | Component | Kind | Symbol / Role |
| --- | ---: | ---: | --- | --- | --- |
| `0x5a80370..0x5a806ea` | 890 | 794/890 (89.2%) | `node-runtime` | `serde_serialize` | `node/src/gossip_rpc.rs` `<GossipRpcRequest as serde::Serialize>::serialize` (`serde_json` compact) |
| `0x5aa9710..0x5aa9848` | 312 | 286/312 (91.7%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<GossipStatus as bincode_fork::Encode>::encode` (`SizeWriter`) |
| `0x5aa9850..0x5aa99d7` | 391 | 363/391 (92.8%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<GossipStatus as bincode_fork::Encode>::encode` (`VecWriter`) |
| `0x5aaa630..0x5aaa735` | 261 | 241/261 (92.3%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<(NodeIp, PeerInfo) as bincode_fork::Encode>::encode` (`VecWriter`, callee of `0x58272e0`) |
| `0x5aaa740..0x5aaa808` | 200 | 173/200 (86.5%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<&GossipRpcRequest as bincode_fork::Encode>::encode` (`SizeWriter`) |
| `0x5aaa810..0x5aaab63` | 851 | 735/851 (86.4%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<&GossipRpcResponse as bincode_fork::Encode>::encode` (`VecWriter`) |
| `0x5aaab70..0x5aaac38` | 200 | 172/200 (86.0%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<&GossipRpcRequest as bincode_fork::Encode>::encode` (`VecWriter`) |
| `0x5aaac40..0x5aaaf54` | 788 | 674/788 (85.5%) | `node-runtime` | `bincode_encode` | `node/src/gossip_rpc.rs` `<&GossipRpcResponse as bincode_fork::Encode>::encode` (`SizeWriter`) |
| **Total** | **3,893** | **3,438/3,893 (88.3%)** | **`node-runtime`** | **8 FDEs** | **Ready for Wave-8 first-party consolidation** |

## Structural Findings Proven to Machine-Code Identity

1. **`GossipRpcResponse` (`0x5aaa810` `851 B` VecWriter + `0x5aaac40` `788 B` SizeWriter = `1,639 B`)**:
   - Exact 3-variant gossip RPC response enum (`ClientBlocks(Result<Vec<ClientBlock>, ClientBlocksError>)`, `Peers(PeersMap)`, `GossipStatus(Option<GossipStatus>)`) with 3-value niche discrimination (`subq $3, %rcx; movl $2, %eax; cmovaeq`) and exact `PeersMap` small-or-large representation (`Small(VecDeque<PeerEntry>)` niched on `VecDeque::cap == 0x8000_0000_0000_0000` vs `Large(BTreeSet<PeerEntry>)`), matching both `VecWriter` and `SizeWriter` FDEs with 0 non-relocation diffs.
2. **`GossipRpcRequest` (`0x5a80370` `890 B` `serde_json::Serialize` + `0x5aaa740` `200 B` SW + `0x5aaab70` `200 B` Vec = `1,290 B`)**:
   - Exact 3-variant enum (`ClientBlocks { start_round: Round, end_round: Round }`, `Peers`, `GossipStatus`), verified both via direct PC32 `.rodata` string anchors in `serde_json` compact serialization (`"ClientBlocks"`, `"Peers"`, `"GossipStatus"`, `"start_round"`, `"end_round"`) and via both `bincode-fork::Encode` writers.
3. **`GossipStatus` (`0x5aa9710` `312 B` SizeWriter + `0x5aa9850` `391 B` VecWriter = `703 B`)**:
   - Exact 4-scalar + trailing `Option<Round>` struct layout (with `Option<Round>` niched at `+0x00` and a nested `RoundPair` at `+0x20..+0x30`), called directly by `GossipRpcResponse::GossipStatus`.
4. **`PeerEntry` `(NodeIp, PeerInfo)` (`0x5aaa630`, `261 B`, `92.3%` raw-equal)**:
   - Direct callee of `0x58272e0` (`VecDeque::encode` inside `GossipRpcResponse::Peers`), encoding 1-variant enum `NodeIp::Ip(Ipv4Addr)` (variant tag `0u32` + 4 octets via `Ipv4Addr::octets()`) followed by `PeerInfo { is_validator: bool, ts: u64 }`.

## Reproduction & Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-transport-runtime-logic-wave3-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-005-node115-transport-runtime-logic-wave3-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_transport_runtime_logic_wave3_byte_matches_115 -v
```
