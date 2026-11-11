# RE-012: recover node #115 guard registry node erase and repair gate

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The guard-registry deletion path calls this helper with a node handle and key index. It saves the indexed key from node +8+8*i and copies the trailing keys left with memmove for 8*(count-i-1) bytes. The corresponding 40-byte value is retained from node +0x60+40*i. The second memmove compacts its trailing values over the removed slot for 40*(count-i-1) bytes. Both calls bind to the same GLOB_DAT entry 0x64df568.

The helper decrements the u16 count at +0x21a only after the two moves. A remaining count above four skips this initial repair dispatch. At four or below, a null parent also bypasses sibling selection. With a parent, the child-position u16 at +0x218 selects whether a left sibling can be inspected or whether the alternate sibling arm is needed. This packet records the erase transaction and initial repair gate independently of the caller's root promotion and allocation cleanup.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-guard-node-erase-115/collect.py --out work/node115-snapshot-guard-node-erase-fresh
python3 -B research/work-items/RE-012-snapshot-guard-node-erase-115/verify.py --out work/node115-snapshot-guard-node-erase-check-fresh.json
```
