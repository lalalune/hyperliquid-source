# RE-012 snapshot paired-field serializer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF VAs.

The shared snapshot array serializer calls 0x22b9660 at 0x2529d6d. This packet maps the two literal keys and the distinct value dispatches in that callee.

The object path checks the writer depth at +0x18 against all ones, increments it, clears the byte at +0x20 and appends an opening brace. It passes the 11-byte key at 0x5ea8e2, book_orders, to 0x26077c0. On the selected success route it appends colon and space and calls 0x229aa10. A nonzero result skips the second key. The next path sets writer +0x20 to 1, passes the 18-byte key untriggered_orders from 0x5ea8ed to the same key helper and dispatches the value to 0x2538070 after the colon and space. The two value schemas and original source names remain open.

The retained full FDE spans 484 bytes and 121 instructions. GNU, LLVM and Capstone agree on the instruction partition. GNU readelf confirms the extent. Replay rejected four code mutations, two literal mutations and two target-identity changes. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-paired-fields-115/collect.py --out work/snapshot-paired-fields-fresh
python3 -B research/work-items/RE-012-snapshot-paired-fields-115/verify.py --out work/snapshot-paired-fields-check-fresh.json
```
