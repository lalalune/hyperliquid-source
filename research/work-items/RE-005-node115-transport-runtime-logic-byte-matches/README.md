# RE-005: Node #115 First-Party `transport` & `node-runtime` Logic Compiled-Byte FDE Matches (`6,117 B`)

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler**: `rustc +1.95.0` (`--edition=2021`, `-C opt-level=3`, `-C overflow-checks=true`, `-C lto=thin`, `-C codegen-units=16`, `#![forbid(unsafe_code)]`, 0 external dependencies)
- **Source kind**: `first-party clean-room rebuild` (zero `core::`/`alloc::`/`std::` or third-party dependency attribution)
- **Matched coverage**: **8 strictly disjoint exact `.eh_frame` FDEs = `6,117 B`** (`5,372 / 6,117 = 87.82%` raw-equal bytes; 100.00% strict `tools/byte_progress.py::compare` relocation-qualified identity, 0 non-relocation byte differences, 0 overlaps against `research/byte-windows.json` and all sibling packets)
  - **`transport`**: **5 FDEs = `2,435 B`** (`2` `bincode_fork::Decode` wire codecs = `718 B`, `1` `Display::fmt` wire error formatter = `394 B`, `2` inlined first-party `<&T as Debug>::fmt` formatters = `1,323 B`)
  - **`node-runtime`**: **3 FDEs = `3,682 B`** (`GossipConfigInner::fmt` = `462 B` + both ThinLTO CGU copies of the 22-variant niche-tagged `NodeError::fmt` = `2 × 1,610 B = 3,220 B`)

## Verified FDE Windows (`8/8` strict relocation-qualified matches)

| Node #115 FDE VA | Size (B) | Raw-Equal | Component | Kind | Symbol / Role |
| --- | ---: | ---: | --- | --- | --- |
| `0x2e464f0..0x2e466a7` | 439 | 400/439 (91.1%) | `transport` | `bincode_decode` | `<ClientBlocksError as bincode_fork::Decode>::decode::<DecoderImpl<SliceReader, Configuration>>` |
| `0x564a710..0x564ad5a` | 1,610 | 1,409/1,610 (87.5%) | `node-runtime` | `debug_fmt` | `<NodeError as core::fmt::Debug>::fmt` (CGU 1, 22-variant niche-tagged over 46-variant `ConsensusError`) |
| `0x5656a20..0x5656bee` | 462 | 402/462 (87.0%) | `node-runtime` | `debug_fmt` | `<GossipConfigInner as core::fmt::Debug>::fmt` (6-field gossip config struct) |
| `0x5a2d540..0x5a2d788` | 584 | 496/584 (84.9%) | `transport` | `debug_fmt` | `<&ClientBlocksError as core::fmt::Debug>::fmt` (inlined first-party `ClientBlocksError::fmt` body) |
| `0x5a2e730..0x5a2ea13` | 739 | 663/739 (89.7%) | `transport` | `debug_fmt` | `<&GossipRpcResponse as core::fmt::Debug>::fmt` (inlined first-party 3-variant niche-tagged `GossipRpcResponse::fmt` body) |
| `0x5a8a880..0x5a8aeca` | 1,610 | 1,401/1,610 (87.0%) | `node-runtime` | `debug_fmt` | `<NodeError as core::fmt::Debug>::fmt` (CGU 2, ThinLTO twin of `0x564a710`) |
| `0x5aaa0c0..0x5aaa24a` | 394 | 342/394 (86.8%) | `transport` | `display_fmt` | `<ClientBlocksError as core::fmt::Display>::fmt` (7-variant wire error `Display`) |
| `0x5aac6a0..0x5aac7b7` | 279 | 259/279 (92.8%) | `transport` | `bincode_decode` | `<GossipRpcRequest as bincode_fork::Decode>::decode::<DecoderImpl<SliceReader, Configuration>>` |
| **Total** | **6,117** | **5,372/6,117 (87.8%)** | **`transport` + `node-runtime`** | **8 FDEs** | **Ready for Wave-7 first-party consolidation** |

## Structural Findings Proven to Machine-Code Identity

1. **`ClientBlocksError` (`0x2e464f0` Decode, `0x5aaa0c0` Display, `0x5a2d540` Debug)**:
   - Exact 7-variant wire order verified across all three FDEs: `0: PeerOnlyRequest`, `1: InvalidRange { start_round, end_round }`, `2: RangeTooLarge`, `3: RateLimited`, `4: NoClientBlocks`, `5: RoundTooSmall { start_round, first_parent_round }`, `6: RoundTooLarge { end_round, max_round }`.
   - `Display::fmt` binds `let (field0, field1) = (start_round, end_round)` before `write!` (matching `thiserror::Error` expansion) and matches all 394 bytes (`342/394` raw-equal, `0` non-relocation diffs).
2. **`GossipRpcRequest` (`0x5aac6a0` Decode)** and **`GossipRpcResponse` (`0x5a2e730` Debug)**:
   - `GossipRpcRequest` wire enum order: `0: ClientBlocks { start_round, end_round }`, `1: Peers`, `2: GossipStatus`.
   - `GossipRpcResponse` is niche-tagged at offset `+0x00` (`sub $3, %rdx; mov $2, %ecx; cmovae %rdx, %rcx`) over a 3-variant `u64`-aligned tag in `GossipStatus` (`0: ClientBlocks`, `1: Peers`, `2: GossipStatus`).
3. **`GossipConfigInner` (`0x5656a20` Debug)**:
   - Exact 6 fields: `root_node_ips: Vec<RootIp>`, `try_new_peers: bool`, `chain: Chain`, `reserved_peer_ips: Vec<ReservedIp>`, `n_gossip_peers: Option<usize>`, `split_client_blocks: bool`, with distinct `Vec` element types for `root_node_ips` vs `reserved_peer_ips` (distinct `Debug` vtables).
4. **`NodeError` (`0x564a710` & `0x5a8a880` Debug — `2 × 1,610 B = 3,220 B`)**:
   - Exact 22-variant runtime error enum niche-tagged into `ConsensusError`'s 46-variant discriminant at offset `+0x00` (`sub $0x2e, %al; mov $3, %ecx; cmovae %eax, %ecx`).
   - Variant `4: QueryClientBlocks(Round, ClientBlocksError)` keeps field 0 at `+0x08` and field 1 at `+0x10` (align-8 non-niche payload), matching both CGU copies (`1,409/1,610` and `1,401/1,610` raw-equal, `0` non-relocation diffs).

## Reproduction & Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-transport-runtime-logic-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-005-node115-transport-runtime-logic-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_transport_runtime_logic_byte_matches_115 -v
```
