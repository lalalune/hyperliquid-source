# RE-012: map node #115 snapshot alternate output buffer handoff

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate descriptor route reaches 0x227e2e0. The worker checks the count-prefix result for tag 2 before the selected copy. It calls memcpy through 0x64df508 and releases via 0x64df4a0 separately. Its later growth route checks the stack status against 1. The unwind route uses the release slot before resuming.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-output-handoff-115/collect.py --out work/node115-snapshot-binary-output-handoff-fresh
python3 -B research/work-items/RE-012-snapshot-binary-output-handoff-115/verify.py --out work/node115-snapshot-binary-output-handoff-check-fresh.json
```
