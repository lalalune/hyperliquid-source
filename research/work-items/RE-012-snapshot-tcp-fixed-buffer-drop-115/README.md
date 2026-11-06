# RE-012: map node #115 TCP fixed buffer and outer release

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the first zero-count callback in the TCP paired-reference array. The caller at 0x5ce8e25 loads its target through slot 0x64e17b0, whose RELATIVE addend is 0x5ce8880.

This callback dereferences the supplied array field and releases the pointer at allocation+0x10 with size 0x800 and third argument zero. Only after that call does it compare the allocation pointer with all ones. On the non-sentinel branch it atomically decrements allocation+8, and only a zero result tail-calls the release slot on the allocation itself, with size 0x28. The ordering is material: the sentinel gate applies to the second stage, and does not precede the first field access. This establishes separate inner and outer allocation lifetimes and does not infer whether a sentinel is reachable at this caller.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-fixed-buffer-drop-115/collect.py --out work/node115-snapshot-tcp-fixed-buffer-drop-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-fixed-buffer-drop-115/verify.py --out work/node115-snapshot-tcp-fixed-buffer-drop-check-fresh.json
```
