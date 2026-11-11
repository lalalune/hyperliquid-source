# RE-012: map node #115 snapshot binary paired-field routing

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate descriptor encoder calls 0x22b9850 at 0x221df0f. The helper gates its prefix on writer byte +0xb, passes the count through 0x25e7940 and checks raw result tag 2 before continuing. The subsequent optional key writes use the literal spans book_orders and untriggered_orders through 0x25e8750 at separate sites. Between them it calls 0x22718d0; after the second key it calls 0x22269f0. This establishes the binary writer's field handoffs.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-paired-fields-115/collect.py --out work/node115-snapshot-binary-paired-fields-fresh
python3 -B research/work-items/RE-012-snapshot-binary-paired-fields-115/verify.py --out work/node115-snapshot-binary-paired-fields-check-fresh.json
```
