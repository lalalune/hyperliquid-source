# RE-012: map node #115 snapshot binary dbOrder header path

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The binary order object passes dbOrder to 0x25ddab0. The entry tests writer +0xb and uses distinct map and count prefix calls. Both raw first words are compared with 2 before the named-key path reaches 0x25e8750. This binds the binary inner record header rather than the textual field prefix.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-db-order-115/collect.py --out work/node115-snapshot-binary-db-order-fresh
python3 -B research/work-items/RE-012-snapshot-binary-db-order-115/verify.py --out work/node115-snapshot-binary-db-order-check-fresh.json
```
