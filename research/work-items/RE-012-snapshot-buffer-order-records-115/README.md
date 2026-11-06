# RE-012: map node #115 snapshot paired buffer order-record dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The paired-buffer writer and book dispatcher converge on 0x2206130. This worker tests writer byte +0x1c, validates the first result word after 0x25e7c10, and dispatches selected records through 0x22b8590. Its output adapter at 0x227e1b0 differs from the 0x227e2e0 handoff used by the alternate writer. The packet records those exact branch and call boundaries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-buffer-order-records-115/collect.py --out work/node115-snapshot-buffer-order-records-fresh
python3 -B research/work-items/RE-012-snapshot-buffer-order-records-115/verify.py --out work/node115-snapshot-buffer-order-records-check-fresh.json
```
