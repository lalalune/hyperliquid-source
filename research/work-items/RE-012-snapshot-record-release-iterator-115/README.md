# RE-012: map node #115 record release iterator

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The record cleanup driver calls 0x24fc8f0 after its tag test. The helper checks the entry pointer and retains two loop regions with separate nonzero size tests before calls through R12. The recorded cursor checks and indirect sites separate the two release paths. The allocator and source element types are outside this packet.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-record-release-iterator-115/collect.py --out work/node115-snapshot-record-release-iterator-fresh
python3 -B research/work-items/RE-012-snapshot-record-release-iterator-115/verify.py --out work/node115-snapshot-record-release-iterator-check-fresh.json
```
