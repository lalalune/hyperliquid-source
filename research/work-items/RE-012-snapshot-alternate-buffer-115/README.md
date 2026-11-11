# RE-012: map node #115 snapshot alternate buffer dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The mode-1 snapshot writer calls 0x2299b30 after suffix selection. This worker calls 0x25e7940 twice at distinct stages and compares each returned first word with 2. The path between those gates calls 0x2297b60. A later dispatch calls 0x25e9c70 and applies another tag-2 check before the output route. The terminal helper at 0x221dc30 and subsequent length comparison are retained separately. The packet records the staged result flow and its error exits; it does not assign Rust variant names to the observed raw tags.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-buffer-115/collect.py --out work/node115-snapshot-alternate-buffer-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-buffer-115/verify.py --out work/node115-snapshot-alternate-buffer-check-fresh.json
```
