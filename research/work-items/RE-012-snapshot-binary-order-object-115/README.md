# RE-012: map node #115 snapshot binary order object

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The binary record adapter selects 0x23f73d0 for its tag-1 route. This worker checks writer byte +0xb before the map-prefix call at 0x23f7403. It separately checks tag 2 after the map and count helper calls. For the named routes it passes dbOrder and priorityRate as literal key spans to 0x25e8750. The first field dispatches to 0x25ddab0, and one arm of the second field, gated by the dword at +0xa8, calls 0x25e9c70. This maps the binary object route beneath the record adapter. The underlying field representations remain open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-order-object-115/collect.py --out work/node115-snapshot-binary-order-object-fresh
python3 -B research/work-items/RE-012-snapshot-binary-order-object-115/verify.py --out work/node115-snapshot-binary-order-object-check-fresh.json
```
