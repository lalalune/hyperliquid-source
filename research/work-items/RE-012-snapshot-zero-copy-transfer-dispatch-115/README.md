# RE-012: map node #115 splice and sendfile transfer fallback

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The second argument selects the splice arm when nonzero and the sendfile64 arm when zero. The ELF GLOB_DAT slots at 0x64ec9f0 and 0x64ec9f8 identify the imports. Each arm checks a separate cached availability byte. With the selected byte set, the worker issues transfers in chunks of min(remaining, 0x7ffff000) and accumulates each positive return. Zero stops the loop and -1 enters the shared errno path. Normal completion publishes tag zero and the accumulated count.

Errno 1 or 38 clears the selected availability byte, using the saved selector's low byte. With zero progress it publishes tag two, as does errno 22 with zero progress. For those cases after positive progress, the path passes the accumulated count to a diagnostic call followed by UD2. Other errors generally publish tag one with the partial count and the packed errno word, with a separate tag-two exception for errno 75 and a zero selector low byte. A disabled availability gate publishes tag two and zero progress without an import call.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-zero-copy-transfer-dispatch-115/collect.py --out work/node115-snapshot-zero-copy-transfer-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-zero-copy-transfer-dispatch-115/verify.py --out work/node115-snapshot-zero-copy-transfer-dispatch-check-fresh.json
```
