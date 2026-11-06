# RE-012: map node #115 snapshot binary payload transfer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate snapshot binary prefix at 0x25e7d40 has a wrapper at 0x25e8220 that handles payload transfer. It checks the returned first word against 2 before the payload path. The growth route calls 0x231dc90 and checks the stack status against 1. The selected transfer calls the memcpy import, and a separate route reaches 0x231e050. This packet binds the status and capacity gates between header generation and copying the payload. The source-level input type remains unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-payload-transfer-115/collect.py --out work/node115-snapshot-binary-payload-transfer-fresh
python3 -B research/work-items/RE-012-snapshot-binary-payload-transfer-115/verify.py --out work/node115-snapshot-binary-payload-transfer-check-fresh.json
```
