# RE-012: map node #115 formatter literal stream consumption

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the initial literal stream consumer at 0x1680500, reached by the shape formatter and cited as an open callee in the RE-014 table shim packet. On the rcx-bit-zero-clear path, the stream starts at rdx. A zero tag exits through 0x16806ab. For tags 1 through 127 the unsigned tag is the slice length, the following byte is the slice start, and sink table+0x18 is called with those operands. Nonzero AL selects the early exit at 0x16806af; otherwise the stream cursor advances past the slice to the next tag. A tag with its high bit set selects the separate branch at 0x1680590. This pins the literal branch only, leaving encoded directives and odd fourth operands outside scope.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-format-literal-stream-115/collect.py --out work/node115-snapshot-format-literal-stream-fresh
python3 -B research/work-items/RE-012-snapshot-format-literal-stream-115/verify.py --out work/node115-snapshot-format-literal-stream-check-fresh.json
```
