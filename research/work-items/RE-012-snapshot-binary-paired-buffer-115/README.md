# RE-012: map node #115 snapshot binary paired-buffer writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate descriptor encoder reaches 0x22b99c0. The worker calls 0x2270260 twice with the descriptor at 0x5ea8db. Both calls are followed by distinct checks on writer byte +0x1b and remaining room. The second group reaches 0x2206130 and checks a result word after the call. This binds the buffer-writer variant independently of the +0xb writer at 0x22b9850.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-paired-buffer-115/collect.py --out work/node115-snapshot-binary-paired-buffer-fresh
python3 -B research/work-items/RE-012-snapshot-binary-paired-buffer-115/verify.py --out work/node115-snapshot-binary-paired-buffer-check-fresh.json
```
