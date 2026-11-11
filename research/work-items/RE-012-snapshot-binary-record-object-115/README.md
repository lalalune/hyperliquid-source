# RE-012: map node #115 snapshot binary record object adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

After its first child, the non-tag-1 binary record adapter calls 0x2294f40. The worker gates both 0x25e7940 and 0x25e9c70 results on raw tag 2 before the observed release and eventual dispatch to 0x23f73d0. The packet retains the exact calls and branches and leaves source-level result names open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-record-object-115/collect.py --out work/node115-snapshot-binary-record-object-fresh
python3 -B research/work-items/RE-012-snapshot-binary-record-object-115/verify.py --out work/node115-snapshot-binary-record-object-check-fresh.json
```
