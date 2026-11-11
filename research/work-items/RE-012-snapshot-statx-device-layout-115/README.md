# RE-012: recover node #115 statx device-number conversion

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The metadata helper's statx path checks the imported entry at 0x64ec9a0, forwards the descriptor/path/flags and passes a request mask of 0xfff. The result buffer begins at rbp-0x130. Return -1 branches away before the success stores.

Two pairs of statx device-number words at offsets 0x80/0x84 and 0x88/0x8c are converted to packed device identifiers. For each major/minor pair the code combines ((major & 0xfff) << 8), ((major & 0xfffff000) << 32), (minor & 0xff), and ((minor & 0xffffff00) << 12), with widening for the high portions. The second input pair goes to output +0x20 and the first to +0x48. The success representation writes tag one, widens the returned mode to a dword at +0x38, and copies the first metadata mask to +0x18. This documents the metadata producer's statx conversion rather than its caller's read-capacity selection.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-statx-device-layout-115/collect.py --out work/node115-snapshot-statx-device-layout-fresh
python3 -B research/work-items/RE-012-snapshot-statx-device-layout-115/verify.py --out work/node115-snapshot-statx-device-layout-check-fresh.json
```
