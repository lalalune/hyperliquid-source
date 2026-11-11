# RE-012: map node #115 nested formatter sink selection

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the nested formatter passed by 0x5ce1740 at 0x5ce17f0. This body starts by sending a two-byte literal to the sink callback at table+0x18 and returns one if the callback returns nonzero in AL. Otherwise it tests bit 7 of formatter+0x12. The clear arm emits one byte and passes the original formatter to 0x5ce98f0. The set arm emits two bytes, builds a stack adapter carrying the original sink, table and a pointer to a byte initialized to one, and passes the adapter to the same helper. After successful helper return, the set arm sends another two bytes through the adapter table. Both paths converge on a one-byte final write; its callback result is returned. Intermediate failures exit early. This evidence establishes control flow and sink selection without assigning the original source type.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-dynamic-format-wrapper-115/collect.py --out work/node115-snapshot-dynamic-format-wrapper-fresh
python3 -B research/work-items/RE-012-snapshot-dynamic-format-wrapper-115/verify.py --out work/node115-snapshot-dynamic-format-wrapper-check-fresh.json
```
