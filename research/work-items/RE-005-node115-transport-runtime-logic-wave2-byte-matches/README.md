# RE-005: Node #115 First-Party `transport` & `node-runtime` Logic Wave 2 Compiled-Byte FDE Matches (`3,222 B`)

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Compiler**: `rustc +1.95.0` (`--edition=2021`, `-C opt-level=3`, `-C overflow-checks=true`, `-C lto=thin`, `-C codegen-units=16`, `#![forbid(unsafe_code)]`, 0 external dependencies)
- **Source kind**: `first-party clean-room rebuild` (zero `core::`/`alloc::`/`std::` or third-party dependency attribution)
- **Matched coverage**: **9 strictly disjoint exact `.eh_frame` FDEs = `3,222 B`** (`2,779 / 3,222 = 86.25%` raw-equal bytes; 100.00% strict `tools/byte_progress.py::compare` relocation-qualified identity, 0 non-relocation byte differences, 0 overlaps against `research/byte-windows.json` and all sibling packets)
  - **`transport`**: **5 FDEs = `1,265 B`** (all 5 ThinLTO CGUs of `net_utils` `TcpGreeting` / `&TcpGreeting` `Debug::fmt`)
  - **`node-runtime`**: **4 FDEs = `1,957 B`** (22-variant niche-tagged `<NodeError as Display>::fmt` = `1,177 B`, `node/src/hl_node.rs:102:9` decimal `u64` CLI parser = `263 B`, `95.1%` raw-equal, plus `node` gossip `<&ChildPeerStatuses as Debug>::fmt` = `296 B` and `<&ChildPeerStatus as Debug>::fmt` = `221 B`)

## Verified FDE Windows (`9/9` strict relocation-qualified matches)

| Node #115 FDE VA | Size (B) | Raw-Equal | Component | Kind | Symbol / Role |
| --- | ---: | ---: | --- | --- | --- |
| `0x2b40880..0x2b4097d` | 253 | 213/253 (84.2%) | `transport` | `debug_fmt` | `net_utils` `<TcpGreeting as core::fmt::Debug>::fmt` (CGU 1) |
| `0x2c7ca40..0x2c7cb3d` | 253 | 213/253 (84.2%) | `transport` | `debug_fmt` | `net_utils` `<&TcpGreeting as core::fmt::Debug>::fmt` (CGU 2, inlined first-party body) |
| `0x2cd3e80..0x2cd3f7d` | 253 | 213/253 (84.2%) | `transport` | `debug_fmt` | `net_utils` `<TcpGreeting as core::fmt::Debug>::fmt` (CGU 3) |
| `0x4f0d8f0..0x4f0da18` | 296 | 264/296 (89.2%) | `node-runtime` | `debug_fmt` | `node` gossip `<&ChildPeerStatuses as core::fmt::Debug>::fmt` (inlined first-party body) |
| `0x4f0db20..0x4f0dbfd` | 221 | 189/221 (85.5%) | `node-runtime` | `debug_fmt` | `node` gossip `<&ChildPeerStatus as core::fmt::Debug>::fmt` (inlined first-party body) |
| `0x564ad60..0x564b1f9` | 1,177 | 1,003/1,177 (85.2%) | `node-runtime` | `display_fmt` | `node` `<NodeError as core::fmt::Display>::fmt` (22-variant niche-tagged runtime error `Display`) |
| `0x5655de0..0x5655ee7` | 263 | 250/263 (95.1%) | `node-runtime` | `business_logic` | `node/src/hl_node.rs:102:9` decimal `u64` CLI argument parser (`s.parse::<u64>().unwrap()`) |
| `0x57d12a0..0x57d139d` | 253 | 217/253 (85.8%) | `transport` | `debug_fmt` | `net_utils` `<&TcpGreeting as core::fmt::Debug>::fmt` (CGU 4, inlined first-party body) |
| `0x5aa85a0..0x5aa869d` | 253 | 217/253 (85.8%) | `transport` | `debug_fmt` | `net_utils` `<TcpGreeting as core::fmt::Debug>::fmt` (CGU 5) |
| **Total** | **3,222** | **2,779/3,222 (86.3%)** | **`transport` + `node-runtime`** | **9 FDEs** | **Ready for Wave-7/8 first-party consolidation** |

## Structural Findings Proven to Machine-Code Identity

1. **`NodeError::Display` (`0x564ad60`, `1,177 B`)**:
   - Exact 22-variant `thiserror::Error` `Display::fmt` matching the exact niche-tagged `NodeError` layout proved in `RE-005-node115-transport-runtime-logic-byte-matches` (`sub $0x2e, %al; mov $3, %ecx; cmovae %eax, %ecx`, jump table `0x92882c`), including `QueryClientBlocks(Round, Round)` (`Could not query client blocks for rounds {0}-{1}`), `L1HashHeightMismatch(Height, Height)`, `L1HashMismatch(L1Hash, L1Hash)`, `AbciDigestMismatch(H256, H256)`, and `InvalidConfigFln { fln, err }`.
2. **`node/src/hl_node.rs:102:9` CLI decimal `u64` parser (`0x5655de0`, `263 B`, `95.1%` raw-equal)**:
   - Pure first-party `hl_node` CLI parser referencing `.data.rel.ro` `Location` `node/src/hl_node.rs:102:9` (`0x64ab4f0`), matching `s.parse::<u64>().unwrap()` with zero non-relocation byte diffs.
3. **`TcpGreeting` (`5 × 253 B = 1,265 B` across 5 ThinLTO CGUs)**:
   - Exact 3-field 1-byte-aligned handshake struct `{ send_abci: bool, broadcast_group: BroadcastGroup, id: TcpId }` at offsets `+0x00, +0x01, +0x02`, emitted as `<TcpGreeting as Debug>::fmt` in CGUs 1, 3, 5 (`0x2b40880`, `0x2cd3e80`, `0x5aa85a0`) and as `<&TcpGreeting as Debug>::fmt` in CGUs 2, 4 (`0x2c7ca40`, `0x57d12a0`).
4. **`ChildPeerStatuses` (`0x4f0d8f0`, `296 B`) & `ChildPeerStatus` (`0x4f0db20`, `221 B`)**:
   - Gossip peer-status types `ChildPeerStatuses(InnerStatuses)` and `ChildPeerStatus { verified: bool, connection_count: usize }` (laid out with `connection_count` at `+0x00` and `verified` at `+0x08`).

## Reproduction & Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-transport-runtime-logic-wave2-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-005-node115-transport-runtime-logic-wave2-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_transport_runtime_logic_wave2_byte_matches_115 -v
```
