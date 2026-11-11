# RE-012: map node #115 TCP paired reference array release

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the nonzero-tag zero-count callback's paired-reference array, which is absent from the selected zero-tag release layout. The caller's slot 0x64dfdc8 relocates to this callback.

At 0x5ce8dc8 the count comes from +0xa0 and the base from +0x98. A zero count skips the array. Otherwise the loop reads pairs at 16-byte stride. It atomically decrements the counter referenced by the first qword and calls slot 0x64e17b0 only on zero, passing the address of that qword. It then independently decrements the counter referenced by the second qword and calls slot 0x64e17a8 only on zero, passing the address of the second qword. The second decrement occurs whether or not the first callback ran, conditional on normal return. After the loop, the original base and count times 16 are passed to slot 0x64df4a0 with third argument zero. This isolates the array lifetime without inferring concrete reference types or claiming unwind coverage.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-paired-ref-drop-115/collect.py --out work/node115-snapshot-tcp-paired-ref-drop-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-paired-ref-drop-115/verify.py --out work/node115-snapshot-tcp-paired-ref-drop-check-fresh.json
```
