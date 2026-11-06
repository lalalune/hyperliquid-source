# RE-012: map node #115 callback workspace and result predicate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The wrapper at 0x5ca0810 clears 0x2905 bytes starting at rbp-0x2948. The call at 0x5ca087c passes a separate result area at rbp-0x40, the cleared workspace, the four original arguments, then stack arguments zero and five in ABI order.

The wrapper forms its return byte from three simultaneous comparisons. The byte at result offset 8 must be zero, the qword at offset zero must equal the original second argument, and the qword at offset 0x10 must equal the original fourth argument. The predicate uses bytewise AND, so it returns one only when all three comparisons hold. This scope describes the wrapper contract and leaves the callback's internal state layout and the meaning of its result fields open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-callback-result-predicate-115/collect.py --out work/node115-snapshot-callback-result-predicate-fresh
python3 -B research/work-items/RE-012-snapshot-callback-result-predicate-115/verify.py --out work/node115-snapshot-callback-result-predicate-check-fresh.json
```
