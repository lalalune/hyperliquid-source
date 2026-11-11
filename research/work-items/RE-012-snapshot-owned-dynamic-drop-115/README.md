# RE-012: map node #115 owned dynamic payload cleanup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the ownership gate of the dynamic drop at 0x5ce7d70. It returns if input[0] or input[8] is zero. Otherwise input[8] is the direct payload pointer and input[0x10] is its descriptor. Descriptor[0], when nonnull, is invoked on the payload itself. Descriptor[8] supplies the release size unchanged, and zero skips release. Descriptor[0x10] supplies the value tested against the size and 17 to select a zero third operand or its trailing-zero count. The unwind branch repeats the size and third-operand computation for the saved payload. In contrast to the shared allocation packet, this body neither adjusts the payload pointer past a header nor decrements an outer counter. The descriptor's source type is unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-owned-dynamic-drop-115/collect.py --out work/node115-snapshot-owned-dynamic-drop-fresh
python3 -B research/work-items/RE-012-snapshot-owned-dynamic-drop-115/verify.py --out work/node115-snapshot-owned-dynamic-drop-check-fresh.json
```
