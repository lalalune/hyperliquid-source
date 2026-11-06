# RE-001: map node115 listener observation in-node insertion moves

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The observer first-node wrapper delegates existing-node insertion here. With occupancy below eleven, the indexed side-record location uses a 24-byte stride. An insertion within the existing occupied range moves the overlapping side records and the separate 608-byte records using memmove; the tail case does not shift either range.

Both selected non-full routes converge on copying a new 608-byte record and storing incremented occupancy. The packet resolves the non-full node insertion layout, leaving the full-node split and upper-level propagation outside its claim.

The retained 1 full FDEs cover 4373 bytes and 870 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-listener-observer-existing-node-insert-115/collect.py --out work/listener-observer-existing-node-insert-fresh
python3 -B research/work-items/RE-001-listener-observer-existing-node-insert-115/verify.py --out work/listener-observer-existing-node-insert-check-fresh.json
```
