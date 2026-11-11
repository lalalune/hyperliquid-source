# RE-012: map node #115 snapshot tagged value dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct tagged field wrapper tail-jumps to 0x25da5c0 when its value tag differs from 5. This callee uses a jump table and has distinct capacity checks in the target blocks, including thresholds 2, 13 and 16. The retained evidence separates tag dispatch from the output room checks and shared exits. It leaves the source variant names unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tagged-value-dispatch-115/collect.py --out work/node115-snapshot-tagged-value-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-tagged-value-dispatch-115/verify.py --out work/node115-snapshot-tagged-value-dispatch-check-fresh.json
```
