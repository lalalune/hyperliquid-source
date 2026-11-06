# RE-001: map node115 gossip report tree cursor descent and next entry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The tree representation of the report peer sequence delegates next-entry selection to this helper. A zero remaining count returns a null result; otherwise the helper decrements the remaining count and requires state tag one. The initial path descends through first-child pointers for the recorded depth. At an exhausted node, the advance path follows parent pointers and tests the recorded child slot against parent occupancy, then can descend through a right-side subtree.

The yielded pointers address the parallel dword array at +0xb8 and a 16-byte entry in the same node. The helper publishes updated cursor words before return. This captures the iterator-to-serializer contract without inferring peer identity fields or claiming a complete malformed-tree validator.

The retained 1 full FDEs cover 548 bytes and 126 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-tree-iterator-115/collect.py --out work/gossip-report-tree-iterator-fresh
python3 -B research/work-items/RE-001-gossip-report-tree-iterator-115/verify.py --out work/gossip-report-tree-iterator-check-fresh.json
```
