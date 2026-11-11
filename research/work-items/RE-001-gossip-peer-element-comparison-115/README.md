# RE-001: resolve node115 gossip snapshot element comparison and exhaustion

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The earlier gossip snapshot adapter ends at the call to 0x4e56dc0. This callee normalizes its current elements from the two input cursor representations. In the selected right-hand span path it advances a 24-byte pointer and tests the dword at element offset zero, then the qword and byte at offsets eight and sixteen. The selected tree path reads the dword from the separate array at node +0xb8 and the qword and byte from a 16-byte entry, then joins the same two-field comparison. A mismatch returns false.

On left-side exhaustion the span arm tests both remaining endpoint pairs via XOR and OR before returning equality. The other arm checks remaining count and, where applicable, the current slot against node occupancy before following parent links. This packet records field and termination behavior without treating padding as part of equality or assigning domain meanings to the three fields.

The retained 1 full FDEs cover 1651 bytes and 395 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-peer-element-comparison-115/collect.py --out work/gossip-peer-element-comparison-fresh
python3 -B research/work-items/RE-001-gossip-peer-element-comparison-115/verify.py --out work/gossip-peer-element-comparison-check-fresh.json
```
