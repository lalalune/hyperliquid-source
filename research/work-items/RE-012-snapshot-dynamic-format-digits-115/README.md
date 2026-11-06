# RE-012: map node #115 formatter four-digit extraction

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: map the default numeric path of the formatter called from 0x5ce1530. The callee loads a qword through the input pointer and checks formatter+0x10 for masks 0x02000000 and 0x04000000 before entering the default branch. Values below 1000 bypass the four-digit loop. The loop multiplies the unsigned input by 0x346dc5d63886594b, takes the high half shifted right 11, and uses that value to subtract a multiple of 10000. The low 32-bit remainder is multiplied by 0x147b and shifted right 19, then split using a multiple of 100. The resulting pair indices load words from the table at 0x46ea12. These are the actual selected operands and branches; alternate format flags and sink behavior are outside this packet.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-dynamic-format-digits-115/collect.py --out work/node115-snapshot-dynamic-format-digits-fresh
python3 -B research/work-items/RE-012-snapshot-dynamic-format-digits-115/verify.py --out work/node115-snapshot-dynamic-format-digits-check-fresh.json
```
