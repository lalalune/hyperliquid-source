# RE-012: map node #115 dynamic formatting shape selection

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: distinguish the three descriptor shapes in the formatting adapter at 0x5ce1740. Two ELF RELATIVE entries, 0x645b2c0 and 0x64e8a40, resolve to this body. A null input+8 selects the record at 0x43d46d without calling the descriptor. Otherwise table+0x18 is called with a stack output and input+8. The first SIMD comparison accepts only a full 16-byte match against 0x454c30 and selects payload qwords +8/+16. On mismatch the routine invokes the same callback again and compares the new output against 0x4503e0; full equality then selects payload qwords +0/+8. Both matches build a two-argument record and select 0x440798. The remaining mismatch builds the single-argument record and selects 0x44b184. All paths converge at the same formatting slot 0x64df6f0. This establishes byte equality, call multiplicity and operand locations without inferring source-level type names.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-dynamic-format-shapes-115/collect.py --out work/node115-snapshot-dynamic-format-shapes-fresh
python3 -B research/work-items/RE-012-snapshot-dynamic-format-shapes-115/verify.py --out work/node115-snapshot-dynamic-format-shapes-check-fresh.json
```
