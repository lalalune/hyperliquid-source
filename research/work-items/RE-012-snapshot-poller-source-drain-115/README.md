# RE-012: recover node #115 poller source drain ownership order

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This poller cleanup routine snapshots a pointer range from the object returned by 0x5cf9230. Its loop uses an eight-byte stride and records the next cursor before touching the current source. Each source receives a locked OR of 0x80000000 at +0x90, then a call to 0x5cfd1d0 with source +0x80 and mask 0x3f. It decrements the retained source reference only after that call and invokes the release helper when the count reaches zero.

An empty range skips the per-source body but still calls 0x5cfe450 on the iterator state. The packet maps ordering across the state flag, notification, and release, leaving notification internals as a boundary. It complements source registration and polling without repeating either.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-poller-source-drain-115/collect.py --out work/node115-snapshot-poller-source-drain-fresh
python3 -B research/work-items/RE-012-snapshot-poller-source-drain-115/verify.py --out work/node115-snapshot-poller-source-drain-check-fresh.json
```
