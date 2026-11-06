# RE-012: recover node #115 signal selector table dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The helper gates the signed selector before touching the shared table. Nonpositive values, or values up to 19 selected by bitmask 0x80b10, take the formatted-error arm. The remaining path checks the input handle against all ones and rejects a null dereference before using the shared table.

The table index is the zero-extended selector minus one, checked against the published count at 0x64fee30. Each entry has stride 32. A nonzero field at +0x18 runs a preparation helper before re-reading +0x10. State zero selects a fixed diagnostic, state two selects the handler through 0x5cfcf90, and other states pack the entry dword at +0x14 with low tag two. This maps the selector and entry-state dispatch without assigning names to the table states.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-signal-selector-table-115/collect.py --out work/node115-snapshot-signal-selector-table-fresh
python3 -B research/work-items/RE-012-snapshot-signal-selector-table-115/verify.py --out work/node115-snapshot-signal-selector-table-check-fresh.json
```
