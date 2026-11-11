# RE-001: map node115 command rendering record collection and failure handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The startup command renderer delegates record collection to this function. It advances over 16-byte source records, calls the slice extraction helper, and skips zero-length extractions. The bound transform returns a three-word record; the first word distinguishes high-bit-plus-one, high-bit-plus-two, and ordinary values. High-bit-plus-one sets the caller-supplied failure byte. High-bit-plus-two skips the source entry.

The first retained record allocates 96 bytes for four 24-byte entries. Later accepted records grow on capacity equality and update the count after all three words are stored. A failure before the first append returns an empty record; after prior appends it returns the partial vector together with the failure byte so the caller can release it. The transform and its quoting rules remain opaque.

The retained 1 full FDEs cover 714 bytes and 169 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-rendered-argument-records-115/collect.py --out work/startup-rendered-argument-records-fresh
python3 -B research/work-items/RE-001-startup-rendered-argument-records-115/verify.py --out work/startup-rendered-argument-records-check-fresh.json
```
