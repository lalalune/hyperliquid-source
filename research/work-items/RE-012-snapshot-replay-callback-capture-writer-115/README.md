# RE-017: trace node #115 replay callback capture writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The entry-checkpoint packet already tracks a state-derived word into callback +0x5e8. PR #3875 instead identifies +0x708 as the replay worker's initial expected word. These offsets have different immediate producers on the selected construction route.

At 0x2cb983e the parent loads [RBX+0x9a8] and at 0x2cb9845 stages it at RSP+0xe38. The allocation call requests 0x718 bytes; a null result takes 0x2cb9de8 before the copy. With a nonnull result the copy at 0x2cb9874 takes RSP+0x730 as source and length 0x718. Thus the staged word lands at allocation +0x708 (0xe38 minus 0x730), beyond the earlier 0x6c0-byte copy into the staging record. The copy slot 0x64df508 is the same memcpy import used by that earlier copy. This is a conditional static writer chain, assuming the helper and subsequent dispatch preserve the copied bytes.

The existing state-derived +0x5e8 projection does not identify the value of parent +0x9a8. The initialization of that parent field, equality or arithmetic relation to checkpoint height, and the first queue segment and slot are still open. No runtime replay is claimed.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-replay-callback-capture-writer-115/collect.py --out work/node115-snapshot-replay-callback-capture-writer-fresh
python3 -B research/work-items/RE-012-snapshot-replay-callback-capture-writer-115/verify.py --out work/node115-snapshot-replay-callback-capture-writer-check-fresh.json
```
