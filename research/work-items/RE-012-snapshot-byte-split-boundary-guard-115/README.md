# RE-012: map node #115 byte split boundary validation

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The guard first subtracts the split index from the slice length and takes the dedicated diagnostic branch on unsigned underflow. That branch references the nine bytes spelling `mid > len` at 0x94928b as part of its diagnostic payload. Otherwise the guard validates a forward window starting at the split index, with length min(4, length minus index), using slot 0x64dfca8.

Only result tag one with zero in the next qword enters the backward-probe path. That path tries windows ending at the split index, starting with length two and increasing up to min(4, index). A backward validation result with first qword zero returns normally. If the probe cannot begin or exhausts those lengths without such a result, the worker formats the split index into a separate diagnostic. This packet records the caller-side boundary logic and leaves the shared validator's internals outside the window.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-byte-split-boundary-guard-115/collect.py --out work/node115-snapshot-byte-split-boundary-guard-fresh
python3 -B research/work-items/RE-012-snapshot-byte-split-boundary-guard-115/verify.py --out work/node115-snapshot-byte-split-boundary-guard-check-fresh.json
```
