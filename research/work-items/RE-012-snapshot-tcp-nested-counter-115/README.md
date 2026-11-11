# RE-012: map node #115 TCP nested reference release

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the second zero-count callback in the paired-reference array. The indirect call at 0x5ce8e35 uses slot 0x64e17a8, whose ELF RELATIVE addend is 0x5ce8620.

This callback dereferences the supplied field and atomically decrements a separate object reached through allocation+0x10. A zero result invokes the slot at 0x64ecbe0 with the address of the +0x10 field. Its addend is 0x5ce89c0. Upon ordinary continuation, the all-ones allocation pointer is the guard for the allocation+8 decrement. A zero result there releases the outer allocation using size 0x30 and third argument zero. This distinguishes it from the first callback's unconditional 0x800-byte inner release and 0x28-byte outer layout. The nested target's internal lifetime and malformed pointers are outside this packet.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-nested-counter-115/collect.py --out work/node115-snapshot-tcp-nested-counter-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-nested-counter-115/verify.py --out work/node115-snapshot-tcp-nested-counter-check-fresh.json
```
