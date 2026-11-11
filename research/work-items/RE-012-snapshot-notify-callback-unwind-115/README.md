# RE-012: bind node #115 notification callback unwind edges

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: bind the exception edge of the two-callback cleanup invoked at 0x5ce8983 from the notification object destructor. The normal first slot call is at 0x5ce7d24. The exception table at 0x403394 maps its three-byte instruction to landing address 0x5ce7d46 with action zero. The landing code saves the exception, tests the second table pointer at +0x28, and if present calls its +0x18 entry with the adjacent +0x30 qword before resuming the saved exception. That call at 0x5ce7d56 has an action-one row targeting 0x5ce7d61, which calls through 0x64df4c0. The ordinary second dispatch is instead a tail jump. This closes the exception table edges within this helper without claiming the concrete types of either callback.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-notify-callback-unwind-115/collect.py --out work/node115-snapshot-notify-callback-unwind-fresh
python3 -B research/work-items/RE-012-snapshot-notify-callback-unwind-115/verify.py --out work/node115-snapshot-notify-callback-unwind-check-fresh.json
```
