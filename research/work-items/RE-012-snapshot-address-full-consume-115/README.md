# RE-012: map node #115 address full-consumption gate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: identify the full-consumption gate above the IPv6 wrapper. The owner at 0x5ca7d60 calls the IPv4 reader at 0x5ca7d8c and checks its low return bit and remaining length. Its other parse path calls 0x167d090 at 0x5ca7e0d, requires stack result tag one, then checks that the descriptor's remaining qword is zero. The IPv6 tag failure and nonzero remaining length both enter 0x5ca7e31, which calls 0x5c9b9c0 with the saved arguments. Only the tag-one and zero-remaining path reaches the observed 0x20-byte allocation. This distinguishes the owner's acceptance gate from prefix success in the IPv6 wrapper; the fallback's resolution behavior remains open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-address-full-consume-115/collect.py --out work/node115-snapshot-address-full-consume-fresh
python3 -B research/work-items/RE-012-snapshot-address-full-consume-115/verify.py --out work/node115-snapshot-address-full-consume-check-fresh.json
```
