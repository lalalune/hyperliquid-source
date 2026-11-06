# RE-012: map node #115 snapshot direct integer width routing

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct record adapters call 0x25e9f10 for the numeric value. The worker tests the input against 256 and 65,536 at separate sites and checks remaining room against 1, 3 and 7 in its width-specific blocks. Capacity paths call 0x231e050. This binds the direct writer's width and capacity dispatch without claiming a complete numeric schema.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-integer-width-115/collect.py --out work/node115-snapshot-direct-integer-width-fresh
python3 -B research/work-items/RE-012-snapshot-direct-integer-width-115/verify.py --out work/node115-snapshot-direct-integer-width-check-fresh.json
```
