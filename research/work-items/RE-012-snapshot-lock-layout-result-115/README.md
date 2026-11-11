# RE-012: map node #115 notification allocation result layout

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: establish the allocator result layout produced for the notification storage growth caller. This resolves the branch behind the prior descriptor commit, at a separate FDE.

The routine forms target bytes as new_count<<6 and rejects either nonzero high six count bits or byte size above 0x7fffffffffffffc0. The reject path stores tag 1 and zero at result+8. For a valid layout, nonzero old count selects slot 0x64df580 with old pointer, new bytes and 6. Zero old count selects slot 0x64df590 with new bytes and 6. Both accept a nonnull returned pointer and place it at result+8, with tag zero. On null they instead write 0x40 at +8 with tag 1. Both allocator outcomes also write the computed bytes at +0x10. The invalid-layout path does not write +0x10. These are raw observed writes, without assigning source-level enum types or treating inactive fields as initialized.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-layout-result-115/collect.py --out work/node115-snapshot-lock-layout-result-fresh
python3 -B research/work-items/RE-012-snapshot-lock-layout-result-115/verify.py --out work/node115-snapshot-lock-layout-result-check-fresh.json
```
