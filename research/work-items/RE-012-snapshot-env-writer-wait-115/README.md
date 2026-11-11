# RE-012: recover node #115 environment writer contended wait

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The failed environment writer fast path reaches this helper through RELATIVE slot 0x64ec670. It can claim a state whose low 30 bits are zero by ORing the acquisition mask and using locked compare-exchange. When the low bits are occupied and bit 31 is clear, it tries to set bit 31 before preparing to wait.

The waiter snapshots the adjacent dword at +4 and rechecks the main word. It waits only if the low bits remain occupied, bit 31 remains set, and the adjacent dword still matches. The syscall uses the adjacent word, operation 0x89, the sampled value and bitset 0xffffffff. On errno four it returns to the adjacent-word comparison. The acquisition mask becomes 0xbfffffff after entering this preparation path. These observations establish the waiter address and recheck order, complementing the distinct release-side handoff.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-env-writer-wait-115/collect.py --out work/node115-snapshot-env-writer-wait-fresh
python3 -B research/work-items/RE-012-snapshot-env-writer-wait-115/verify.py --out work/node115-snapshot-env-writer-wait-check-fresh.json
```
