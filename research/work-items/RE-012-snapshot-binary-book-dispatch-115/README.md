# RE-012: map node #115 snapshot binary book dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The book_orders branch from 0x22b9850 calls 0x22718d0. The callee distinguishes writer byte +0xc equal to 2, uses two separate count-header call sites, and compares the returned first word with 2 at both. The selected continuation calls 0x22269f0 and checks the returned word against the saved marker. Another continuation hands off to 0x22997f0. The packet binds the distinct paths and raw checks.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-book-dispatch-115/collect.py --out work/node115-snapshot-binary-book-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-binary-book-dispatch-115/verify.py --out work/node115-snapshot-binary-book-dispatch-check-fresh.json
```
