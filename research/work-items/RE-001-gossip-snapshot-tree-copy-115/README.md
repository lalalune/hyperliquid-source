# RE-001: map node115 gossip snapshot recursive tree copy and parent links

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The signed-minimum nonempty snapshot arm delegates its tree representation to this copy helper. Depth zero creates a 0xe8-byte leaf, clears its parent and count, and copies occupied entries from the source with a bound of eleven. Entry writes use a 16-byte stride for the qword and byte, and a separate dword array at +0xb8. The output carries the new root and copied count.

The nonzero-depth arm descends through the first child and allocates a 0x148-byte internal node. It then recursively copies the remaining children, verifies the selected returned height against the first child, and writes child parent pointers and slot indices before publishing the descriptor. This identifies the clone topology, rather than inferring key semantics or valid construction of malformed trees.

The retained 1 full FDEs cover 971 bytes and 204 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-snapshot-tree-copy-115/collect.py --out work/gossip-snapshot-tree-copy-fresh
python3 -B research/work-items/RE-001-gossip-snapshot-tree-copy-115/verify.py --out work/gossip-snapshot-tree-copy-check-fresh.json
```
