# RE-012: map node #115 TCP descriptor vector cleanup order

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the descriptor-and-reference-vector cleanup called by the TCP zero-tag release. Its sentinel is a dword at +0x44, distinct from the qword ownership split in #3679.

If +0x44 is all ones, the routine decrements the reference addressed by the first qword, calls 0x64e17f8 on zero, and skips the ordinary close/vector sequence. Otherwise it saves +0x44, closes the dword at +0x40 through the close import, then iterates +0x20 entries starting at the pointer from +0x18. Each eight-byte entry points to a counter; a zero post-decrement result calls the slot at 0x64dfe38 on the entry address. After the loop, nonzero +0x10 supplies the size in elements for releasing the backing pointer, and only then does it close the saved +0x44 dword. The common continuation excludes both zero and all ones at +0x48 before its final decrement. The packet concerns ordinary ordering, not proof of descriptor provenance or full unwind behavior.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-descriptor-vector-115/collect.py --out work/node115-snapshot-tcp-descriptor-vector-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-descriptor-vector-115/verify.py --out work/node115-snapshot-tcp-descriptor-vector-check-fresh.json
```
