# RE-001: resolve node115 split byte-search fallback and result offsets

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The separator search packet identified the fallback binding at 0x64dfcb0 but left its result contract open. The fallback receives the target byte, pointer and search length. It searches an unaligned prefix before entering an eight-byte-aligned loop. In each complete sixteen-byte block it XORs both words with the repeated target byte and uses subtraction and high-bit masks to decide whether to skip the block. A possible hit transfers to scalar comparison at the block start rather than returning a word-level estimate.

The scalar tail returns tag one with a zero-based byte index for the first equality. Exhaustion returns tag zero. The caller therefore uses this result only as a candidate position; full separator validation stays with the caller. This packet uses the caller-established minimum search window of sixteen bytes.

The retained 1 full FDEs cover 215 bytes and 68 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-byte-search-fallback-115/collect.py --out work/startup-byte-search-fallback-fresh
python3 -B research/work-items/RE-001-startup-byte-search-fallback-115/verify.py --out work/startup-byte-search-fallback-check-fresh.json
```
