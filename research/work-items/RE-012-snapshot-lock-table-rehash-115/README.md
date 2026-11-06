# RE-012: map node #115 notification waiter rehash and publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: map notification table replacement and waiter migration. Earlier entry-word research lists 0x5bb6070 as a family member but leaves its individual role open.

After constructing a candidate at 0x5bb6223, the selected nonempty path walks the previous array in 64-byte steps. It skips empty heads and saves each node's next pointer before mutating it. For each node it multiplies the key at node+0 by 0x9e3779b97f4a7c15 modulo 64 bits, shifts by 64 minus the new descriptor's +0x18 dword, and checks the resulting index against new descriptor+8. It appends to the new bucket, writing the new head if its tail was null and otherwise writing the former tail's next pointer. It then writes the new tail, zeroes the appended node's next pointer, and continues through the saved old next. After the scan, 0x5bb62e9 writes the new table pointer and the following loop decrements old bucket words with locked XADD. The packet establishes selected migration order and links, without claiming the entire contention protocol.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-table-rehash-115/collect.py --out work/node115-snapshot-lock-table-rehash-fresh
python3 -B research/work-items/RE-012-snapshot-lock-table-rehash-115/verify.py --out work/node115-snapshot-lock-table-rehash-check-fresh.json
```
