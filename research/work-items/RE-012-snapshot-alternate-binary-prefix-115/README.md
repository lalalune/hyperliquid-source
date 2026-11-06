# RE-012: map node #115 snapshot alternate binary prefix

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate buffer tail calls 0x25e7d40 at 0x229985c. This worker selects a binary-length marker family distinct from the count marker family: it compares EDX against 256 and 65,536, and the retained paths use 0xc4, 0xc5 and 0xc6. The shared marker helper is called before the header write, while the growth route calls 0x231dc90 and tests the separate stack status. This packet captures the width transitions and buffer handoff without assigning a source-level payload type.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-binary-prefix-115/collect.py --out work/node115-snapshot-alternate-binary-prefix-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-binary-prefix-115/verify.py --out work/node115-snapshot-alternate-binary-prefix-check-fresh.json
```
