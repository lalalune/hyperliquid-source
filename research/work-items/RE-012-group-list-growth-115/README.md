# RE-012: map node115 supplementary group query growth and handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected group query calls getgrouplist with a count
slot and the owned vector storage. Return -1 enters a loop.
It compares capacity minus current length with 255 and
calls the growth helper with requested spare count 256 and
four-byte layout arguments when needed.

Each retry resets the count slot to the current capacity
and uses the current vector pointer. A return other than -1
commits the updated count as length and constructs a range
whose end is base plus count times four. It hands that range
to 0x5cb9190. This packet follows vector ownership and retry,
without querying the host group database.

The retained 1 full FDEs cover 1879 bytes and 455 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-group-list-growth-115/collect.py --out work/group-list-growth-fresh
python3 -B research/work-items/RE-012-group-list-growth-115/verify.py --out work/group-list-growth-check-fresh.json
```
