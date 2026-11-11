# RE-001: map node115 listener hash block and pending-tail update

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The earlier fixed-width listener hash packet stops at the call to 0x4ecead0. This routine adds the input length at state +0x30 and appends incoming bytes to the pending little-endian word at +0x38 when +0x40 is nonzero. If the supplied bytes cannot fill that word it updates the pending count and returns. Otherwise the completed word passes through the add/rotate/XOR round before processing full input words.

Each full word advances the input by eight bytes. The remaining length modulo eight determines the dword, word and byte loads used to construct the next pending word. The routine stores that word and its byte count separately. This maps the previously open streaming input boundary without asserting a source algorithm name.

The retained 1 full FDEs cover 471 bytes and 141 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-listener-hash-tail-update-115/collect.py --out work/listener-hash-tail-update-fresh
python3 -B research/work-items/RE-001-listener-hash-tail-update-115/verify.py --out work/listener-hash-tail-update-check-fresh.json
```
