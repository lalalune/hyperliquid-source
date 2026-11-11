# RE-012: map node #115 TCP pair dynamic finalizer dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012 transport question: when does the nested pair cleanup transfer control to its dynamic finalizer? Earlier gate evidence mentions 0x2abc7e0 as drop_pair at a different caller. TCP cleanup reaches it from 0x2aaa4b0 and 0x2aaa4ce.

A full 32-bit tag of 2 returns immediately. Otherwise the initial slot 0x64dfe40 resolves to 0x5ceafd0 via ELF RELATIVE, before the low-byte dispatch and reference decrement. Normal continuation loads the table pointer from +0x30. A null pointer returns; a nonnull pointer tail-jumps through table+0x18 with the +0x38 value in rdi. The exceptional continuation at 0x2abc84a performs the same null gate but uses a call before resuming the saved unwind. The alternate entry at 0x2abc83f first invokes 0x2ab7550 on the original object. This pins both dispatch conventions without identifying a concrete dynamic table or source type.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-pair-finalizer-115/collect.py --out work/node115-snapshot-tcp-pair-finalizer-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-pair-finalizer-115/verify.py --out work/node115-snapshot-tcp-pair-finalizer-check-fresh.json
```
