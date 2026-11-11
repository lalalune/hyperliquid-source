# RE-012: map node #115 snapshot integer prefix formatter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The mode-1 snapshot worker calls 0x26d4420 at 0x26a6195 and appends the returned pointer/length before the next separator. This packet follows the formatter and pins the table at 0x5f4348. The entry compares against 10,000, and the large-value path reduces the remainder in four-digit groups. It converts two-digit indices with two-byte table loads. The final tail chooses a single ASCII digit or a table pair depending on the remaining value. The worker returns a pointer inside the supplied destination span and a length, with an explicit bound check at 0x26d4532. The business meaning of the formatted value remains open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-integer-prefix-115/collect.py --out work/node115-snapshot-integer-prefix-fresh
python3 -B research/work-items/RE-012-snapshot-integer-prefix-115/verify.py --out work/node115-snapshot-integer-prefix-check-fresh.json
```
