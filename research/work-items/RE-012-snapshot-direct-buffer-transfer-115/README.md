# RE-012: map node #115 snapshot direct buffer transfer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The paired-buffer order-record worker uses 0x227e1b0 as its transfer adapter. It gates the copy after the direct count-prefix result, calls memcpy and uses the release slot separately. Its capacity route calls 0x231e050 directly. An unwind route invokes the release slot before resuming.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-buffer-transfer-115/collect.py --out work/node115-snapshot-direct-buffer-transfer-fresh
python3 -B research/work-items/RE-012-snapshot-direct-buffer-transfer-115/verify.py --out work/node115-snapshot-direct-buffer-transfer-check-fresh.json
```
