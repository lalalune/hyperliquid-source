# RE-012: recover node #115 buffer growth capacity policy

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The growth helper checks unsigned overflow when adding the current logical length and the requested additional count. If the sum fits, it chooses the larger of the sum and twice the stored capacity. The doubling instruction itself has no carry check. The helper then applies a floor of eight when the last input word equals one and four otherwise.

It forwards the old capacity, old pointer, chosen capacity and preserved layout inputs to 0x5c8b9f0. A result tag of one branches to the error helper. On success the new pointer and capacity replace the old descriptor fields; the logical length is outside these stores. This recovers the capacity policy used by the readlink and bounded read paths rather than duplicating their read loops.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-buffer-growth-policy-115/collect.py --out work/node115-snapshot-buffer-growth-policy-fresh
python3 -B research/work-items/RE-012-snapshot-buffer-growth-policy-115/verify.py --out work/node115-snapshot-buffer-growth-policy-check-fresh.json
```
