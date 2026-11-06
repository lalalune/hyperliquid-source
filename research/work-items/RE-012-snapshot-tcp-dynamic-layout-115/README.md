# RE-012: resolve node #115 dynamic release layout operands

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the layout-dependent callback shared by the four-reference TCP cleanup. Slot 0x64e17c8 resolves to this FDE. The two input qwords supply an allocation base and a descriptor. If descriptor[0] is nonzero, it is called with base + ((descriptor[0x10] - 1) & ~15) + 16, using wrapping machine arithmetic. Upon normal return, an all-ones base skips the decrement. Otherwise the locked decrement at base+8 gates the outer release. On zero, the routine chooses a = max(8, descriptor[0x10]) and computes the size operand (descriptor[8] + a + 15) & -a. Zero size skips the release. The third operand defaults to zero and takes TZCNT(a) if a exceeds that size or the low dword of descriptor[0x10] is at least 17. The separate unwind continuation calls 0x5ce7e00 before resuming. These are observed operands; this packet does not assume a descriptor type or validate malformed layouts.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-dynamic-layout-115/collect.py --out work/node115-snapshot-tcp-dynamic-layout-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-dynamic-layout-115/verify.py --out work/node115-snapshot-tcp-dynamic-layout-check-fresh.json
```
