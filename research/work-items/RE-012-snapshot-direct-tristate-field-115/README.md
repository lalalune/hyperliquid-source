# RE-012: map node #115 snapshot direct tagged field

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct dbOrder encoder calls 0x260eef0 at 0x25de2ff. The helper reads writer byte +0x1b before an optional key append through 0x25e8bf0. It then compares the value's leading byte with 5 and checks the remaining writer capacity on the selected path before emitting the value. The growth branch calls 0x231e050. The retained bytes delimit the descriptor test and writer handoff; the original field type and tag names remain unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-tristate-field-115/collect.py --out work/node115-snapshot-direct-tristate-field-fresh
python3 -B research/work-items/RE-012-snapshot-direct-tristate-field-115/verify.py --out work/node115-snapshot-direct-tristate-field-check-fresh.json
```
