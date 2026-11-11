# RE-012: resolve node #115 contended byte lock transitions

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the contended byte lock called by the detach path through slot 0x64e01f8. Prior evidence records the argument and the entry address but does not establish the selected byte transitions.

At 0x5bb5a60 the helper tests bit 0 of the observed byte. If clear it tries to set bit 0 while preserving all other bits with a locked byte CMPXCHG. Success branches to 0x5bb5ffc. On the held branch it tests bit 1. If that bit is already set, it goes directly to the later wait preparation. Otherwise the unsigned counter test at 0x5bb5a68 allows values 0 through 9 to branch away before attempting to set bit 1. The latter attempt ORs the observed byte with 2 and retries the observation loop on CMPXCHG failure. Wait preparation then clears the stack qword at +0x78 and checks the byte at +0x28 of the object saved in stack slot +0x18. This packet establishes the pre-wait transition predicates, without assigning a source enum or claiming the full parking policy.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-byte-contended-115/collect.py --out work/node115-snapshot-lock-byte-contended-fresh
python3 -B research/work-items/RE-012-snapshot-lock-byte-contended-115/verify.py --out work/node115-snapshot-lock-byte-contended-check-fresh.json
```
