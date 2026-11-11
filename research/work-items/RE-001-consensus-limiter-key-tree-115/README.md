# RE-001: map node115 listener limiter fixed-width tree lookup

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The consensus listener evidence identifies 0x595ec00 as a caller boundary. This packet maps the function entry tree search. It loads a root pointer and a depth-like word from the supplied object. The node occupancy word at +0xe6 bounds a scan starting at node +8 with 20-byte stride. Each key comparison calls memcmp with an explicit width of 20. Positive results advance to the next key, equality terminates the search, and a negative result selects the current child index.

Exhaustion instead uses the occupancy as the child index. Descent reads an eight-byte child slot from node +0xe8 and requires the depth word to allow another level. The packet separates this lookup from subsequent mutable accounting and does not infer the key origin or policy from the comparison alone.

The retained 1 full FDEs cover 1751 bytes and 400 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-limiter-key-tree-115/collect.py --out work/consensus-limiter-key-tree-fresh
python3 -B research/work-items/RE-001-consensus-limiter-key-tree-115/verify.py --out work/consensus-limiter-key-tree-check-fresh.json
```
