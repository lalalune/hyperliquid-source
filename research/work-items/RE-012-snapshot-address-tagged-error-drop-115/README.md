# RE-012: map node #115 address error ownership tags

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the error-value cleanup called for unsupported address families by the result iterator. The first qword's low two bits select the ownership path: only tag one reaches the payload. The wrapper base is the tagged qword minus one, its first two qwords yield the payload and descriptor, and the descriptor's optional first entry is called with that payload. A nonzero descriptor size then reaches a payload release. Regardless of that size, the ordinary path releases the separate wrapper with size 0x18. Tags zero, two and three return before either release. This binds the tag and two ownership layers without asserting the source error type.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-address-tagged-error-drop-115/collect.py --out work/node115-snapshot-address-tagged-error-drop-fresh
python3 -B research/work-items/RE-012-snapshot-address-tagged-error-drop-115/verify.py --out work/node115-snapshot-address-tagged-error-drop-check-fresh.json
```
