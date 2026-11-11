# RE-012: map node #115 snapshot binary float wire

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The writer at 0x25e8340 emits marker 0xca followed by four bytes from the XMM0 low word. It transfers the bits into EAX and applies BSWAP before the four-byte store. Marker and payload room are checked independently. A growth route saves the XMM0 bits on the stack, calls 0x231dc90 and checks the result status before restoring the bits. This establishes the wire byte order and preservation across growth.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-f32-wire-115/collect.py --out work/node115-snapshot-binary-f32-wire-fresh
python3 -B research/work-items/RE-012-snapshot-binary-f32-wire-115/verify.py --out work/node115-snapshot-binary-f32-wire-check-fresh.json
```
