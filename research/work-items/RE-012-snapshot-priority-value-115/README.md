# RE-012: map node #115 snapshot optional priority value

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The order object writer passes priorityRate to 0x25922d0. This wrapper calls the key helper, checks its descriptor byte, then selects the field value using the source byte at offset zero. Zero emits the four literal bytes null. Nonzero reads the dword at source +4 and calls 0x243bf10. The returned span is compared with available capacity, a zero-length copy is skipped, and successful completion sets the writer state byte at +0x20 to 1. The formatter's own numeric semantics remain open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-priority-value-115/collect.py --out work/node115-snapshot-priority-value-fresh
python3 -B research/work-items/RE-012-snapshot-priority-value-115/verify.py --out work/node115-snapshot-priority-value-check-fresh.json
```
