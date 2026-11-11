# RE-001: map node115 gossip snapshot representation and lock release

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The existing peer-status packet reaches this snapshot helper after the poll delay. The helper acquires the word at owner +0x10 by adding 16 via locked compare-exchange. Bit three, the upper saturation boundary, or a failed compare-exchange routes through the bound slow helper. Under this acquisition it distinguishes the signed-minimum representation at +0x18 from the ordinary clone path. The tagged representation with zero count uses the empty arm; the nonempty one calls a separate copy helper. Both publish four descriptor words.

The ordinary release subtracts 16 through locked xadd and calls the bound wake helper only when the prior word masked with 0xfffffffffffffff2 equals 0x12. The unwind landing path uses the same subtraction and predicate before resuming. This closes the snapshot wrapper ownership around the copy without assigning a meaning to the slow-lock argument or reconstructing either copy callee.

The retained 1 full FDEs cover 343 bytes and 88 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-peer-snapshot-lock-115/collect.py --out work/gossip-peer-snapshot-lock-fresh
python3 -B research/work-items/RE-001-gossip-peer-snapshot-lock-115/verify.py --out work/gossip-peer-snapshot-lock-check-fresh.json
```
