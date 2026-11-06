# RE-012: map node #115 snapshot binary string payload append

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate descriptor path calls 0x25e8bf0. Its length thresholds are 32, 256 and 65,536. Besides the capacity branches for the header itself, a separate branch compares the full source length with remaining capacity before calling the memcpy import. This records the additional payload bound and copy boundary.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-string-append-115/collect.py --out work/node115-snapshot-binary-string-append-fresh
python3 -B research/work-items/RE-012-snapshot-binary-string-append-115/verify.py --out work/node115-snapshot-binary-string-append-check-fresh.json
```
