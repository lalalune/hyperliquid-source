# RE-012: recover node #115 staged formatter output length gate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The formatting wrapper dispatches on mask 0x18 in formatter byte +0x13. Its selected staged arm starts with a zero byte count and builds adapter entries for the object, the optional dword at +0x14 and the word at +0x18. The dword's zero check chooses another packed format program and argument layout. The wrapper passes a temporary output state and writer table 0x6408038 to the shared interpreter.

After a successful staged write the wrapper loads the resulting byte count and admits only values strictly below 0x3b. It then forwards the exact count and stack buffer to slot 0x64df720 with the original output formatter. Interpreter failure and oversized staged results go to separate diagnostic paths. The other top-level arm formats directly or constructs a shorter direct adapter. This packet recovers the bounded staging transaction and its output gate.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-staged-format-width-115/collect.py --out work/node115-snapshot-staged-format-width-fresh
python3 -B research/work-items/RE-012-snapshot-staged-format-width-115/verify.py --out work/node115-snapshot-staged-format-width-check-fresh.json
```
