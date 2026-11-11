# RE-012: map node #115 snapshot object key framing

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

Snapshot object writers use 0x26077c0 for quoted keys. The entry checks the descriptor bytes at offsets zero and one separately. The retained body includes capacity branches for delimiter writes and a repeated indentation copy. After the prefix, the key body is passed to 0x25bf330 at 0x26078fa. The following capacity check precedes the closing quote write. The packet maps key framing and buffer transitions, leaving escape-table semantics to the separate escaping worker.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-object-key-115/collect.py --out work/node115-snapshot-object-key-fresh
python3 -B research/work-items/RE-012-snapshot-object-key-115/verify.py --out work/node115-snapshot-object-key-check-fresh.json
```
