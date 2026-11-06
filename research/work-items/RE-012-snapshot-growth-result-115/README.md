# RE-012: map node #115 snapshot allocator result routing

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate snapshot prefix writers call 0x231dc90 for buffer growth. This packet follows that helper's allocation routing and result publication. With a nonzero existing-size input it chooses between slots 0x64df580 and 0x64df588. The branch uses both the requested alignment threshold of 17 and its comparison with the requested size, followed by a trailing-zero test. The zero-existing-size route uses separate slots 0x64df590 and 0x64df480 and handles a zero request without an allocation call. After a called allocator returns, the function tests RAX before populating the result words. The allocator bodies and original source-level result type remain open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-growth-result-115/collect.py --out work/node115-snapshot-growth-result-fresh
python3 -B research/work-items/RE-012-snapshot-growth-result-115/verify.py --out work/node115-snapshot-growth-result-check-fresh.json
```
