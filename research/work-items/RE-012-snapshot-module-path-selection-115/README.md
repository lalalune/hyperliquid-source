# RE-012: map node #115 pathname selection and range lookup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This packet maps the pathname selection arms in the function starting at 0x5ca0330. A supplied C string reaches the length call at 0x5ca037f and the byte-copy path at 0x5ca03ab. The zero-address arm builds the NUL-terminated pathname `/proc/self/exe` on the stack and calls the readlink helper at 0x5ca040e.

The table arm reads the base at context offset 0x20 and count at 0x28 after checking the sentinel at 0x18. It advances by 0x30 bytes per row and tests the unsigned half-open range `[row+0x18 value, row+0x20 value)`. A matching row with zero name length at offset 0x10 is skipped. For a matching nonempty row, the name pointer at offset 8 and length at offset 0x10 feed the shared copy path. An absent or exhausted table reaches a second `/proc/self/exe` readlink call at 0x5ca04ff. The packet does not infer a source-level type for the surrounding context.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-module-path-selection-115/collect.py --out work/node115-snapshot-module-path-selection-fresh
python3 -B research/work-items/RE-012-snapshot-module-path-selection-115/verify.py --out work/node115-snapshot-module-path-selection-check-fresh.json
```
