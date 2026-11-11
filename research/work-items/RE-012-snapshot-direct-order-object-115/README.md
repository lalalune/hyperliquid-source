# RE-012: map node #115 snapshot direct binary order object

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The tag-1 buffer record adapter calls 0x23f7170. This direct-buffer route tests +0x1b before its first field and reaches 0x25ddf30. A separate +0x1b check governs the later prefix; the dword at +0xa8 gates the route reaching 0x25e9f10 and the following tag-2 result test. These sites distinguish the direct writer from the +0xb order object.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-order-object-115/collect.py --out work/node115-snapshot-direct-order-object-fresh
python3 -B research/work-items/RE-012-snapshot-direct-order-object-115/verify.py --out work/node115-snapshot-direct-order-object-check-fresh.json
```
