# RE-012: map node #115 notification storage growth commit

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the constructor's growth handoff beyond the initial capacity calculation. Relocation 0x64ec190 resolves to 0x5bb6920, which passes descriptor[0] in rsi to this routine.

The selected helper computes max(4, max(rsi+1, 2*descriptor[0])) with unsigned comparisons and machine-width wrapping in the arithmetic before comparison. It passes the previous capacity and pointer, and the new capacity, to 0x5bb6950 with stack storage for the result. A nonzero result byte returns the two result qwords in rax and rdx without updating the descriptor. A zero result byte stores the returned pointer to descriptor+8, then commits the new capacity at descriptor+0 and returns 0x8000000000000001. The wrapper tests this exact sentinel. This is local storage growth, with no claim about publication of a replacement shared table or rehashing entries.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-table-grow-115/collect.py --out work/node115-snapshot-lock-table-grow-fresh
python3 -B research/work-items/RE-012-snapshot-lock-table-grow-115/verify.py --out work/node115-snapshot-lock-table-grow-check-fresh.json
```
