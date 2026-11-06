# RE-012: map node #115 snapshot direct count header writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The paired-buffer book path calls 0x25e7c10. The worker uses count thresholds 16 and 65,536 and dispatches explicit 0xdc and 0xdd forms. The capacity paths call 0x231e050 directly, distinct from the result-returning growth path previously mapped at 0x25e7940. This packet binds the direct-growth checks and header branch sites.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-count-header-115/collect.py --out work/node115-snapshot-direct-count-header-fresh
python3 -B research/work-items/RE-012-snapshot-direct-count-header-115/verify.py --out work/node115-snapshot-direct-count-header-check-fresh.json
```
