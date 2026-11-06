# RE-012: map node #115 snapshot alternate buffer tail

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate snapshot buffer worker calls 0x22997f0 at 0x2299db6. The callee has distinct calls to 0x25e7d40 and 0x25e7940. The result of the latter is tested against tag 2 before the later span work. The path reaching 0x231dc90 tests a separate stack status against 1 before the growth and copy tail. The copy slot resolves to memcpy; the unwind route conditionally releases a saved buffer before resuming. The packet binds the staged calls and status checks without assigning a source name to the result representation.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-tail-115/collect.py --out work/node115-snapshot-alternate-tail-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-tail-115/verify.py --out work/node115-snapshot-alternate-tail-check-fresh.json
```
