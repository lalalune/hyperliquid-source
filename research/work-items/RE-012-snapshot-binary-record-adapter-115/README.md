# RE-012: map node #115 snapshot binary record adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The triggered-order writer calls 0x22b8860. A low dword tag of 1 selects 0x23f73d0. The other route tests writer byte +0xc for 2 and compares the count-prefix return to tag 2. Its observed continuation calls 0x22970e0 and 0x2294f40 with independent result-word tests before handing off to 0x22997f0. The packet establishes the adapter's dispatch sequence and leaves the child record types open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-record-adapter-115/collect.py --out work/node115-snapshot-binary-record-adapter-fresh
python3 -B research/work-items/RE-012-snapshot-binary-record-adapter-115/verify.py --out work/node115-snapshot-binary-record-adapter-check-fresh.json
```
