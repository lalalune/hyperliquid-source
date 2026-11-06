# RE-012: map node #115 snapshot direct record object adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The second child of the direct-buffer record adapter uses 0x22984e0. Separate result checks follow its count and value helpers. It reaches the release slot before the selected call to 0x23f7170, the direct-buffer object worker. The packet binds this call sequence and result gates.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-record-object-115/collect.py --out work/node115-snapshot-direct-record-object-fresh
python3 -B research/work-items/RE-012-snapshot-direct-record-object-115/verify.py --out work/node115-snapshot-direct-record-object-check-fresh.json
```
