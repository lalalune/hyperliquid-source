# RE-012: map node #115 notification table capacity and descriptor

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: establish the capacity calculation and descriptor layout of the constructor called by the notification table publication race.

The capacity starts from checked unsigned 3*n. For products below two the candidate mask is zero. Otherwise BSR(product-1), bitwise NOT of the shift register, and a right shift of an all-ones qword produce the low-bit mask for the next power-of-two capacity. Increment forms the capacity and rejects wrap to zero. The allocation byte count is capacity shifted left six, guarded both by a high-bit test and a comparison against 0x7fffffffffffffc0. For the first publication's n=3, this gives product 9, capacity 16 and 1024 initial bucket bytes.

The descriptor allocation at 0x5bb65e3 takes 0x20 bytes. Its stores at 0x5bb65ff..0x5bb6612 write the bucket pointer at +0, the bucket length at +8, the original second constructor argument at +0x10, and the capacity-derived dword at +0x18. This binds the producer side of the fields used for bucket selection, separate from the publication race. The resize call's internal behavior and allocator failure policy are outside scope.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-table-layout-115/collect.py --out work/node115-snapshot-lock-table-layout-fresh
python3 -B research/work-items/RE-012-snapshot-lock-table-layout-115/verify.py --out work/node115-snapshot-lock-table-layout-check-fresh.json
```
