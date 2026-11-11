# RE-012: map node #115 snapshot direct optional formatted value

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct dbOrder route calls 0x260ee30 at 0x25de326. After the optional key append gated by writer +0x1b, the value's first byte is tested against 1. The selected formatting route initializes a stack buffer and calls 0x64e4d08 with immediate arguments 34 and 16, then appends the returned span. The alternate route writes 0xc0 with its own capacity check. The original value type remains open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-optional-hex-115/collect.py --out work/node115-snapshot-direct-optional-hex-fresh
python3 -B research/work-items/RE-012-snapshot-direct-optional-hex-115/verify.py --out work/node115-snapshot-direct-optional-hex-check-fresh.json
```
