# RE-012: recover node #115 descriptor table swap removal and cleanup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This refresh worker scans the descriptor table backwards with a 28-byte stride. It reloads the current logical count before invoking the per-row probe through slot 0x64ec898. A zero result dword and zero adjacent status byte skip removal. Otherwise it rechecks the index against the current count before accessing the row.

The removal arm saves four descriptor dwords from offsets 12, 16, 20 and 24, replaces the current row with the last row using 16-, 8- and 4-byte stores, and decrements the published count. It then closes each saved descriptor independently unless that descriptor equals -1. This maps swap-removal and the ownership order, leaving the probe's internal predicate as a separate boundary.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-descriptor-table-prune-115/collect.py --out work/node115-snapshot-descriptor-table-prune-fresh
python3 -B research/work-items/RE-012-snapshot-descriptor-table-prune-115/verify.py --out work/node115-snapshot-descriptor-table-prune-check-fresh.json
```
