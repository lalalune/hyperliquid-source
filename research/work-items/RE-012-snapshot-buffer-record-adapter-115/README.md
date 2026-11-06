# RE-012: map node #115 snapshot buffer record adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The paired-buffer order-record worker calls 0x22b8590. A low dword tag of 1 selects 0x23f7170. The other route uses writer byte +0x1c and reaches 0x2298dd0 and 0x22984e0 with result-word checks. Its later tail call is 0x22999e0, which is already covered by the upstream fee-rate map wire packet. This packet maps the upstream adapter and the dispatch boundaries into that existing evidence.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-buffer-record-adapter-115/collect.py --out work/node115-snapshot-buffer-record-adapter-fresh
python3 -B research/work-items/RE-012-snapshot-buffer-record-adapter-115/verify.py --out work/node115-snapshot-buffer-record-adapter-check-fresh.json
```
