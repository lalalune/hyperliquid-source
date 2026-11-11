# RE-012: recover node #115 child process debug field writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This formatter emits a Child record and selects three named fields from the input object. The initial table +0x18 call writes the exact five-byte Child literal. Three invocations of the helper through 0x64dfad0 then pair offsets +0x10, +0x14 and +0x18 with the exact literals stdin, stdout and stderr and three separate field descriptors.

The stack adapter retains the initial write status. The finish path returns failure immediately when that status is set. Otherwise the adapter's adjacent state byte and formatting flag 0x80 select the closing operation. The alternate closing path constructs a second stack adapter and calls slot 0x64e00a0, propagating its failure before emitting the final one-byte suffix. This recovers the Child debug representation and its writer protocol independently of any subprocess creation or stream reads.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-child-debug-record-115/collect.py --out work/node115-snapshot-child-debug-record-fresh
python3 -B research/work-items/RE-012-snapshot-child-debug-record-115/verify.py --out work/node115-snapshot-child-debug-record-check-fresh.json
```
