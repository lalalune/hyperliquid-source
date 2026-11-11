# RE-012: recover node #115 child status probe and cache publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The descriptor table's per-row probe checks whether status is already cached using input tag one. That path returns a present result with the cached status. Otherwise a descriptor other than -1 at input +0x0c selects helper 0x5c875f0 with selector five; a -1 descriptor selects waitpid with the PID at +8 and options one.

For waitpid, zero selects a pending result, -1 packs errno with low tag two, and a positive result caches the status at input +4 and sets input tag one. The helper path also caches its status when its inner discriminator equals one. The outer output tag distinguishes errors, while output +4 carries the status-presence value on success. This documents the predicate used by descriptor-table pruning without repeating the removal transaction.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-child-status-probe-115/collect.py --out work/node115-snapshot-child-status-probe-fresh
python3 -B research/work-items/RE-012-snapshot-child-status-probe-115/verify.py --out work/node115-snapshot-child-status-probe-check-fresh.json
```
