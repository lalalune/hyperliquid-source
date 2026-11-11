# RE-012: recover node #115 three-field colon format adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The input wrapper loads one object pointer and copies its first 16 bytes into a stack record. It binds that record to the first formatter callback at 0x5ca7380. It then binds two pointers into the same object, at offsets +0x10 and +0x14, to the shared callback resolved by RELATIVE slot 0x64e0270 (0x1688a20). The first callback instead forwards the copied pointer/length pair to RELATIVE target 0x167fa70.

The formatter receives the original destination pair, a packed program at 0x44ddb5, and the three consecutive pointer/callback entries. The first eight bytes of the program are c0 01 3a c0 01 3a c0 00; the executed program ends at the zero after the third callback token, yielding two literal colon separators. This packet recovers the caller-side adapter construction and its program binding. The shared interpreter is independently described by the upstream flag-group write-target packet.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-three-field-format-adapter-115/collect.py --out work/node115-snapshot-three-field-format-adapter-fresh
python3 -B research/work-items/RE-012-snapshot-three-field-format-adapter-115/verify.py --out work/node115-snapshot-three-field-format-adapter-check-fresh.json
```
