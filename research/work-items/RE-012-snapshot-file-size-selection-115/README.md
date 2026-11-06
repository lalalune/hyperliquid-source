# RE-012: recover node #115 file read capacity hint selection

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This file-read wrapper derives a capacity hint before entering the shared read loop. Its first metadata helper receives the descriptor and the constant 4096. Metadata tag three selects a zero-initialized 144-byte stack record and an fstat64 call through slot 0x64eafe8. On success that arm takes the signed size from record offset 48. The other ordinary arm loads its size from offset 80 of the first metadata result, while tag two takes an error payload from offset 8.

A negative size from either size arm stores the fixed payload 0x2600000003 and the signed-minimum sentinel, then follows the descriptor cleanup path. The fstat64 failure arm captures errno and packs it with low tag two. The shared metadata-error arm drops the temporary error and reaches the read loop with a zero-capacity initial state. This evidence distinguishes a missing hint from an explicitly negative size, without assigning semantics to the producer's unexamined metadata tags.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-file-size-selection-115/collect.py --out work/node115-snapshot-file-size-selection-fresh
python3 -B research/work-items/RE-012-snapshot-file-size-selection-115/verify.py --out work/node115-snapshot-file-size-selection-check-fresh.json
```
