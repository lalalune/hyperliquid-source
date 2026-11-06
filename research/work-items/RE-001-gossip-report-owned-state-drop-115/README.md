# RE-001: map node115 gossip report old-state destruction

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report replacement path calls this destructor on the old record. It invokes the iterator handoff and drain helpers first and conditionally passes a nonzero returned word to a cleanup helper. The word at +0x18 is then tested for signed minimum. That representation skips the nested cleanup, its buffer release and the close call. For the other representation, the selected path invokes the nested cleanup, releases the +0x20 pointer when its size word is nonzero, then passes the dword at +0x34 to close.

The outer allocation at +0x08 is released when its size word is nonzero on either ordinary route. Separate unwind landing blocks protect the remaining owned fields before resuming. The packet maps ownership and the close binding without inferring OS effects.

The retained 1 full FDEs cover 213 bytes and 64 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-owned-state-drop-115/collect.py --out work/gossip-report-owned-state-drop-fresh
python3 -B research/work-items/RE-001-gossip-report-owned-state-drop-115/verify.py --out work/gossip-report-owned-state-drop-check-fresh.json
```
