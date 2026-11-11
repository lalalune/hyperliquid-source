# RE-012: recover node #115 layout allocation dispatch and failure ABI

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The allocation dispatcher multiplies two caller-supplied factors and rejects unsigned product overflow or a product larger than 0x8000000000000000 minus the alignment word. That rejection writes tag one and zero at +8. The accepted path selects fresh allocation versus resizing by testing the old-size argument.

Both branches use the same alignment rule: an alignment below 17 that is no larger than the new byte count selects the ordinary slot. Otherwise the dispatcher computes tzcnt(alignment) and selects the aligned slot only when that value is nonzero. Fresh zero-size requests use the alignment word as the result pointer without calling an allocator. A null allocation writes tag one and the alignment at +8, while success writes tag zero and the pointer there. Both of those result arms preserve the requested byte count at +16. This maps layout checks, four allocator call boundaries, and the result discriminator.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-layout-allocation-dispatch-115/collect.py --out work/node115-snapshot-layout-allocation-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-layout-allocation-dispatch-115/verify.py --out work/node115-snapshot-layout-allocation-dispatch-check-fresh.json
```
