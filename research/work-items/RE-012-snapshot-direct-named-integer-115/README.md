# RE-012: map node #115 snapshot direct named integer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct dbOrder writer calls 0x260f980 at 0x25de191. The helper checks writer +0x1b and uses a separate room check before the value stage. It calls 0x25e9f10 for the value and checks raw tag 2 on return. The packet establishes the field-specific wrapper and raw result gate.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-named-integer-115/collect.py --out work/node115-snapshot-direct-named-integer-fresh
python3 -B research/work-items/RE-012-snapshot-direct-named-integer-115/verify.py --out work/node115-snapshot-direct-named-integer-check-fresh.json
```
