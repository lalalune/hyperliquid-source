# RE-012: map node #115 snapshot direct marker field

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

Multiple direct dbOrder field routes converge at 0x260fb40. It gates the named prefix on +0x1b and calls 0x25e8bf0. Its value block separately checks capacity and calls the marker helper 0x25eab50. This records the wrapper's binding to the already mapped marker machinery.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-marker-field-115/collect.py --out work/node115-snapshot-direct-marker-field-fresh
python3 -B research/work-items/RE-012-snapshot-direct-marker-field-115/verify.py --out work/node115-snapshot-direct-marker-field-check-fresh.json
```
