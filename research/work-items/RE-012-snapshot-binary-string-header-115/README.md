# RE-012: map node #115 snapshot binary string header

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The paired-field path calls 0x25e8750 for named keys. It branches on lengths 32, 256 and 65,536 and uses markers 0xd9, 0xda and 0xdb. The evidence binds the marker branches and the status check after the allocation helper.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-string-header-115/collect.py --out work/node115-snapshot-binary-string-header-fresh
python3 -B research/work-items/RE-012-snapshot-binary-string-header-115/verify.py --out work/node115-snapshot-binary-string-header-check-fresh.json
```
