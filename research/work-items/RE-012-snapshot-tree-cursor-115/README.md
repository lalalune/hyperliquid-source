# RE-012 snapshot tree cursor step

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF VAs.

The shared snapshot serializer calls 0x238e630 from 0x2529ac5. This packet resolves the callee's cursor state and pair return, below the serializer's descriptor dispatch.

A zero qword at cursor +0x40 returns zero in RAX before inspecting the cursor tag. A nonzero count is decremented and stored before checking that the low dword tag is 1. An active node pointer is read from +8. For a nonnull node the unsigned index from +0x18 is compared with the node's 16-bit field at +0x42a. The retained fallback traverses links at node +0x430, with an eight-hop unrolled body.

The selected return block at 0x238e7f1 computes RAX = node + 8 + 24*i and RDX = node + 0x110 + 72*i using the selected index i. It updates cursor +8, clears +0x10 and stores the next index in +0x18. Both diagnostic branches resolve through 0x64df830 to 0x1680c10 and contain UD2 after the call. The element types and original source names remain unresolved.

GNU, LLVM and Capstone agree on 127 instructions over 539 bytes. GNU readelf confirms the single FDE. Replay rejects five instruction-window mutations, one relocation addend mutation and two identity controls. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tree-cursor-115/collect.py --out work/snapshot-tree-cursor-fresh
python3 -B research/work-items/RE-012-snapshot-tree-cursor-115/verify.py --out work/snapshot-tree-cursor-check-fresh.json
```
