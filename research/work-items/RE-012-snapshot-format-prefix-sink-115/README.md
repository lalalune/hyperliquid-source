# RE-012: map node #115 prefix sink callback ordering

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the prefix writer used at 0x167ea59. If the incoming code differs from 0x110000, the helper calls sink table+0x20 with that code. A nonzero returned AL stops before any byte slice is written and returns AL=1. The sentinel skips the code callback entirely. Both successful paths then test the saved slice pointer from rcx. A null pointer returns zero irrespective of the saved length; otherwise the helper tail-jumps through the sink's +0x18 entry with the pointer and original length from r8. This resolves the ordering and failure propagation between two sink slots without assigning concrete dynamic implementations.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-format-prefix-sink-115/collect.py --out work/node115-snapshot-format-prefix-sink-fresh
python3 -B research/work-items/RE-012-snapshot-format-prefix-sink-115/verify.py --out work/node115-snapshot-format-prefix-sink-check-fresh.json
```
