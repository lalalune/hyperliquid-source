# RE-012: map node #115 snapshot direct map prefix

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct dbOrder path at 0x25ddf62 invokes 0x25e7540. The helper selects its count form at thresholds 16 and 65,536, then calls the marker helper 0x25eab50. Its explicit markers are 0xde and 0xdf. The normal branches check room separately for the one-byte marker and the multi-byte forms; the insufficient-room paths invoke 0x231e050 directly. This maps the direct-buffer map prefix independently of the separate allocation-result protocol in 0x25e7670.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-map-header-115/collect.py --out work/node115-snapshot-direct-map-header-fresh
python3 -B research/work-items/RE-012-snapshot-direct-map-header-115/verify.py --out work/node115-snapshot-direct-map-header-check-fresh.json
```
