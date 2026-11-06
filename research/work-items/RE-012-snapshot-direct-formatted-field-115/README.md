# RE-012: map node #115 snapshot direct formatted field

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct dbOrder writer reaches 0x260e470 for a formatted field. It checks +0x1b before the optional key append. The formatter slot at 0x64e5bd8 precedes a separate append call for the value. A release call follows, with a separate release in the unwind path. The packet covers that ownership handoff without naming the numeric representation.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-formatted-field-115/collect.py --out work/node115-snapshot-direct-formatted-field-fresh
python3 -B research/work-items/RE-012-snapshot-direct-formatted-field-115/verify.py --out work/node115-snapshot-direct-formatted-field-check-fresh.json
```
