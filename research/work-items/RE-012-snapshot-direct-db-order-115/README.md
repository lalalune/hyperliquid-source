# RE-012: map node #115 snapshot direct dbOrder header path

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct binary order object calls 0x25ddf30 for dbOrder. This worker tests writer +0x1b, calls map helper 0x25e7540 and count helper 0x25e7c10, and checks each return against raw tag 2. A later +0x1b gate precedes its inline capacity check. This maps the separate direct-buffer dependencies.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-db-order-115/collect.py --out work/node115-snapshot-direct-db-order-fresh
python3 -B research/work-items/RE-012-snapshot-direct-db-order-115/verify.py --out work/node115-snapshot-direct-db-order-check-fresh.json
```
