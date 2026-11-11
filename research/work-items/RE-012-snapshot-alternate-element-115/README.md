# RE-012: map node #115 snapshot alternate element adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate snapshot buffer worker calls 0x2297b60. The callee calls 0x25e7940 and gates further dispatch on result tag 2. One recorded route loads an indexed byte from the source span before 0x25e9c70; the subsequent route reaches the same target at a separate site. The three-word result is published in separate blocks after the tag-2 comparisons. This packet captures those boundaries and the release call without attributing a source enum to the raw words.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-element-115/collect.py --out work/node115-snapshot-alternate-element-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-element-115/verify.py --out work/node115-snapshot-alternate-element-check-fresh.json
```
