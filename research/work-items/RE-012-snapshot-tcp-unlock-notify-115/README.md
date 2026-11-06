# RE-012: map node #115 TCP unlock notification bucket and head match

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: resolve the lock-notification callee reached from TCP detach when the fast release fails. Slot 0x64e0f38 has RELATIVE addend 0x5bb5650. Existing RE-001 entry-word evidence counts this family member but leaves its role open.

The callee keys the lookup on rdi and saves the 32-bit second argument in edx. It multiplies the key modulo 64 bits by 0x9e3779b97f4a7c15, selects the high bits using 64 minus table+0x18, checks that index against table+8, and scales it by 64. The fast bucket acquisition compares its qword with zero and writes one. After acquisition it rechecks the current table pointer against the pointer used for bucket selection. On the stable-table path at 0x5bb577e it loads the queue head at bucket+8 and compares the head's first qword with the original key. When that comparison matches, 0x5bb579f advances the head to the node's +8 link. If bucket+0x10 equals the removed head, 0x5bb583f also updates that endpoint. This binds the selected matching-head case; it does not identify the higher-level scheduling semantics or qualify every competing-table and later-node path.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-unlock-notify-115/collect.py --out work/node115-snapshot-tcp-unlock-notify-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-unlock-notify-115/verify.py --out work/node115-snapshot-tcp-unlock-notify-check-fresh.json
```
