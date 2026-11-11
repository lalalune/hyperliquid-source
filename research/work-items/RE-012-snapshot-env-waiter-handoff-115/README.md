# RE-012: recover node #115 environment lock waiter handoff

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The environment writer's release path dispatches through 0x64ec5b0 to this handoff helper. It rejects an input state with any low 30 bits set via the diagnostic at 0x5c84871. With state 0x80000000 it attempts to clear the main word; on success it increments the adjacent word and wakes one waiter there. A lost compare-exchange replaces the input state with the observed word before resuming dispatch.

State 0xc0000000 is first changed to 0x40000000 via compare-exchange. A successful transition increments the adjacent word and wakes one waiter there. A positive wake result ends the helper. Otherwise it shares the 0x40000000 path, which attempts to clear the main word and, on success, wakes up to INT_MAX on the main word. Both wake calls use syscall number 0xca and operation 0x81. This maps notification address and count, complementing the caller's release threshold.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-env-waiter-handoff-115/collect.py --out work/node115-snapshot-env-waiter-handoff-fresh
python3 -B research/work-items/RE-012-snapshot-env-waiter-handoff-115/verify.py --out work/node115-snapshot-env-waiter-handoff-check-fresh.json
```
