# RE-012: recover node #115 signal registration handle acquisition

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The table lookup called by the selector-state-two arm treats its selector as one-based. Zero takes a dedicated diagnostic. A nonzero selector is decremented and checked against the entry count before a 32-byte stride lookup. The first qword of the selected row supplies the returned object pointer.

Before publication the helper increments the object's leading qword with a locked instruction and traps if the signed result is nonpositive. It reads the generation-shaped qword at +0x138, increments a separate qword at +0x140, and clears bit zero of the saved value for the second return register. This maps the acquired handle and generation payload expected by the caller. The interpretation of the cleared bit remains open.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-signal-registration-handle-115/collect.py --out work/node115-snapshot-signal-registration-handle-fresh
python3 -B research/work-items/RE-012-snapshot-signal-registration-handle-115/verify.py --out work/node115-snapshot-signal-registration-handle-check-fresh.json
```
