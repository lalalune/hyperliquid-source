# RE-012: map node #115 snapshot pair state writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This writer checks the incoming count and the low bit of SIL before using the state pointer at input +0x40. The normal branch sets the state byte at +1 to 2. It calls 0x25bf160 twice with distinct argument pairs, with a single-byte write between them. Each nonzero status reaches the shared conversion call through 0x64e13c8. The source-level state and value types remain open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-pair-state-writer-115/collect.py --out work/node115-snapshot-pair-state-writer-fresh
python3 -B research/work-items/RE-012-snapshot-pair-state-writer-115/verify.py --out work/node115-snapshot-pair-state-writer-check-fresh.json
```
