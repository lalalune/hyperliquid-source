# RE-012: map node #115 TCP shared state drop and unwind

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012 transport: resolve the cleanup called by the sender and its nested drop helper at 0x2aaa460. This packet covers the callee's shared-ownership operation and separate unwind edges.

Both bytes at +0x220 and +0x21a must equal 3. The helper uses +0x88 to choose the zero-count callback and atomically decrements the first qword of the allocation addressed by the pointer at +0x90. A nonzero post-decrement result bypasses the callback in either branch. A zero result uses slot 0x64dfdb8 when +0x88 is zero and 0x64dfdc8 otherwise. The ELF RELATIVE addends are 0x5ce86d0 and 0x5ce8da0, respectively. In either case the normal continuation calls 0x2abc7e0 on object+0x98 and clears byte +0x219.

The LSDA at 0x258edc binds both callbacks to cleanup 0x2aaa4c4, which still calls the +0x98 helper. The ordinary +0x98 call has a distinct landing pad at 0x2aaa4db that skips repeating that call. Both cleanups clear +0x219 before resuming unwind. The +0x98 call during active unwind instead lands at 0x2aaa4d5, through slot 0x64df4c0. Decode the pinned LSDA bytes with the repository parse_lsda helper and the reported FDE bounds. This does not establish Rust type names or the internals of the indirect callbacks.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-shared-drop-115/collect.py --out work/node115-snapshot-tcp-shared-drop-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-shared-drop-115/verify.py --out work/node115-snapshot-tcp-shared-drop-check-fresh.json
```
