# RE-012: map node #115 formatting sign and width gate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the sign and width entry of the sink reached via slot 0x64dfa00. With esi zero, the selected sign code is 0x2d and one is added to the incoming length in r9. With esi nonzero, formatter+0x10 bit 21 selects code 0x2b and length increment one; otherwise the code is 0x110000 and the increment is zero. On the bit-23-clear path the code reads an unsigned 16-bit width at formatter+0x14 and branches to padding handling if the resulting length is below that width. Otherwise it calls 0x1686260, and a nonzero return byte exits with AL set to one before the body write. The successful path loads the output target from the sink table's +0x18 slot. This records the selected branch and does not claim the full padding algorithm.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-format-sign-width-115/collect.py --out work/node115-snapshot-format-sign-width-fresh
python3 -B research/work-items/RE-012-snapshot-format-sign-width-115/verify.py --out work/node115-snapshot-format-sign-width-check-fresh.json
```
