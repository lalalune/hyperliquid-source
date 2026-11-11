# RE-012: recover node #115 file path callback cleanup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The file-read wrapper calls this adapter with a context and callback. It forwards the path inputs to the RELATIVE converter at 0x141e960, then negates the first result qword. Overflow (signed minimum) selects the callback arm, passing the output pointer, context, and the converter's two remaining qwords. The byte at the returned pointer is cleared after callback return, and the storage is released through slot 0x64df4a0 when its retained size is nonzero.

Other converter results store tag one and a fixed descriptor at output +8. The branch at 0x5c78c7b consumes the carry preserved from negation, so a zero first qword skips deallocation. The unwind landing pad also clears the first byte, conditionally releases the buffer and resumes unwinding. This packet describes callback ownership and cleanup, independent of file read sizing.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-file-path-callback-115/collect.py --out work/node115-snapshot-file-path-callback-fresh
python3 -B research/work-items/RE-012-snapshot-file-path-callback-115/verify.py --out work/node115-snapshot-file-path-callback-check-fresh.json
```
