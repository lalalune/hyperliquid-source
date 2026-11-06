# RE-012: map node #115 TCP sender nested drop predicates

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012 transport question: what does the nested cleanup called at sender PC 0x2b7b4f7 release? The previously mapped compression scratch slots are distinct from the object passed to this helper.

The helper returns immediately unless byte +0x2e1 equals 3. In that case it calls 0x2aaa460 on object+0xb8, then calls through 0x64df4a0 using the pointer at +0x60 and size at +0x58 if that size is nonzero. The ordinary continuation tail-calls the same slot for pointer +0x48 when +0x40 is neither zero nor INT64_MIN: NEG skips INT64_MIN through OF and skips zero through CF. This is distinct from the signed-positive condition on the unwind continuation. The exceptional continuation at 0x2ac557a preserves the exception value and checks the same two size fields before resuming unwind. Both releases pass zero in edx. The allocator slot's RELATIVE addend is 0x635de30.

This identifies the selected drop order and predicates, without assigning the tag a Rust enum name or claiming the nested helper's full ownership graph.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-nested-drop-115/collect.py --out work/node115-snapshot-tcp-nested-drop-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-nested-drop-115/verify.py --out work/node115-snapshot-tcp-nested-drop-check-fresh.json
```
