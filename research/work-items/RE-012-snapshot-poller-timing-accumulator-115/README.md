# RE-012: recover node #115 poller timing accumulator and blend

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The timing helper first checks the dword at +0x30 against the one-billion sentinel. For a finite value it samples clock selector one and computes an elapsed pair. It multiplies the seconds word by one billion and adds the fractional word with carry. A nonzero high word saturates the conversion to UINT64_MAX; an elapsed-result flag instead selects zero. The subsequent addition into state +0x10 has its own carry check and branches to a diagnostic before the store on overflow.

A nonzero state count at +0 triggers a second elapsed-time calculation using the saved pair at +0x38/+0x40. The converted sample is divided by the count. The state update at +8 blends that quotient with the previous value using complementary weights derived from pow. The count-zero branch skips the floating-point update. This documents the timing accumulator's independent integer and floating-point gates.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-poller-timing-accumulator-115/collect.py --out work/node115-snapshot-poller-timing-accumulator-fresh
python3 -B research/work-items/RE-012-snapshot-poller-timing-accumulator-115/verify.py --out work/node115-snapshot-poller-timing-accumulator-check-fresh.json
```
