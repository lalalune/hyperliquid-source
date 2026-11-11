# RE-012: map node #115 quoted formatter sink framing

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the quote callback framing reached from the 0x5cdf5d0 formatter thunk. ELF slot 0x64df700 resolves to 0x1689750. The entry loads the sink and table from the two qwords addressed by rdx, then calls table+0x20 with code 0x22. A nonzero AL ends the operation with AL=1 before scanning the input. In the zero-length path the routine still reaches the table+0x18 slice callback with length zero. The shared trailing-slice path calls that slot with the adjusted pointer and length, aborting on nonzero AL. Otherwise it calls the original +0x20 target with 0x22 again and propagates that result. This isolates the framing and error boundaries; it does not characterize the interior escape algorithm.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-format-quoted-sink-115/collect.py --out work/node115-snapshot-format-quoted-sink-fresh
python3 -B research/work-items/RE-012-snapshot-format-quoted-sink-115/verify.py --out work/node115-snapshot-format-quoted-sink-check-fresh.json
```
