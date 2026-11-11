# RE-012: recover node #115 timing state construction and publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The timing constructor rejects a duration pair only when both the seconds and fractional inputs are zero. It then samples clock selector one and obtains a tagged pair via RELATIVE slot 0x64e0848. The low tag bit selects between two timing slots at offsets 0x160 and 0x240 from the returned pointer. The selected slot's dword at +0x90 is checked against the one-billion sentinel before allocation.

The constructor initializes a stack record with the returned pair, state qword two, and the sampled clock pair. It allocates 0x70 bytes and copies the full record. Only after allocation and copy does it publish the heap pointer at output +0x10, the original duration pair at +0/+8, and clear the output flag at +0x18. This packet captures creation and ownership publication, separate from the later normalization and accumulator updates.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-timing-state-constructor-115/collect.py --out work/node115-snapshot-timing-state-constructor-fresh
python3 -B research/work-items/RE-012-snapshot-timing-state-constructor-115/verify.py --out work/node115-snapshot-timing-state-constructor-check-fresh.json
```
