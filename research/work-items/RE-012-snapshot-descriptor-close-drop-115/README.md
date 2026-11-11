# RE-012: map node #115 descriptor close and ownership split

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the ownership split in the descriptor cleanup at 0x5ce22b0. The NEG overflow path selects INT64_MIN at +8 and decrements the counter referenced through +0x10. It tail-dispatches through 0x64e17f8 on zero and bypasses the two close calls. Otherwise a nonzero +8 causes release of the +0x10 pointer with a size of 12 times +8. This path then calls the same imported function on dwords +0x20 and +0x30, in that order. ELF relocation 0x64dfe78 binds the function to close@GLIBC_2.2.5. After those calls the code separately decrements the +0x28 reference and checks the all-ones sentinel at +0x38 before decrementing that object's +8 counter. The last-zero path releases 16 bytes. The observed close arguments and guards do not identify the originating file descriptors or qualify the exception paths.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-descriptor-close-drop-115/collect.py --out work/node115-snapshot-descriptor-close-drop-fresh
python3 -B research/work-items/RE-012-snapshot-descriptor-close-drop-115/verify.py --out work/node115-snapshot-descriptor-close-drop-check-fresh.json
```
