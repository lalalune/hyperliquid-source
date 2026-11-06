# RE-012: recover node #115 checked timing normalization and publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The timing-state update converts two seconds/nanoseconds pairs to 128-bit scalar quantities using a multiply by one billion and a carry-propagating fractional addition. The first quantity must be nonzero before the arithmetic call through slot 0x64dfc68. The other quantity is replaced by zero when the elapsed result flag is nonzero. A nonzero high word returned by that call goes to a separate diagnostic.

The low result is split with reciprocal multiplication and a one-billion multiply-back. The seconds subtraction checks signed overflow. A negative fractional remainder borrows one second, checks that decrement for signed overflow, and adds one billion back to the fraction. The normalized pair is written at state +0x60/+0x68 before the call to 0x5cf1d70. The following store sets the qword at state +0x10 to two. This packet anchors checked normalization and publication order without assigning a higher-level scheduler policy.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-poller-time-normalization-115/collect.py --out work/node115-snapshot-poller-time-normalization-fresh
python3 -B research/work-items/RE-012-snapshot-poller-time-normalization-115/verify.py --out work/node115-snapshot-poller-time-normalization-check-fresh.json
```
