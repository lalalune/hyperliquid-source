# RE-012: map node #115 snapshot paired buffer book dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The +0x1b paired writer calls 0x2270260. Unlike the +0xc path, this worker inspects +0x1c and calls the 0x25e7c10 prefix routine. It checks the returned tag before reaching 0x2206130 at distinct sites. Another route uses 0x22999e0 for its tail. The evidence binds the variant-specific dependencies and status transitions.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-buffer-book-dispatch-115/collect.py --out work/node115-snapshot-buffer-book-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-buffer-book-dispatch-115/verify.py --out work/node115-snapshot-buffer-book-dispatch-check-fresh.json
```
