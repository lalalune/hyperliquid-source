# RE-012: map node #115 snapshot direct record label adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct-buffer record adapter calls 0x2298dd0. Its header and value stages use 0x25e7c10 and 0x25e9f10, with tag-2 tests after both. The selected label route calls the formatter slot and then 0x25e8bf0. This maps the direct-buffer append boundary and distinguishes it from the 0x25e8750 route.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-record-label-115/collect.py --out work/node115-snapshot-direct-record-label-fresh
python3 -B research/work-items/RE-012-snapshot-direct-record-label-115/verify.py --out work/node115-snapshot-direct-record-label-check-fresh.json
```
